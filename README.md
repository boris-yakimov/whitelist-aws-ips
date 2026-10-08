# whitelist-aws-ips

[![CI](https://github.com/boris-yakimov/whitelist-aws-ips/actions/workflows/go.yml/badge.svg)](https://github.com/boris-yakimov/whitelist-aws-ips/actions/workflows/go.yml)

An AWS Lambda function that keeps EC2 security group **egress** rules in sync with the
[published AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
for selected AWS services (e.g. `S3`, `API_GATEWAY`).

Use it to lock down outbound traffic from private workloads to specific AWS services
without opening `0.0.0.0/0`.

## How it works

1. Downloads [`ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json).
2. Compares its `createDate` with the value stored in SSM Parameter Store; if unchanged, the run exits.
3. Selects the IPv4 prefixes of the configured services and widens them to `/16`
   supernets (prefixes already wider than `/16` are kept), removing duplicates and
   overlapping ranges.
4. Reads the current egress rules of the configured security groups and adds a
   `tcp/<port>` rule for every missing CIDR, filling groups in order without
   exceeding the per-group rule limit. Capacity is checked **before** any change is made.
5. Records each added CIDR (with its security group and timestamp) in a DynamoDB table
   for auditing. The table is created on first run.
6. Saves the new `createDate` to SSM — only after all updates succeeded, so a failed
   run is fully retried next time.

The security groups themselves are the source of truth, so runs are idempotent and
safe to repeat. Existing rules are never removed.

> Widening to `/16` trades precision for a manageable number of rules: the allowed
> ranges may include addresses that do not belong to the selected services.

## Configuration

Set as Lambda environment variables:

| Variable                | Required | Default                                          | Description                                              |
|-------------------------|----------|--------------------------------------------------|----------------------------------------------------------|
| `securityGroupIDs`      | yes      | –                                                | Comma-separated security group IDs to manage             |
| `servicesToBeWhitelist` | yes      | –                                                | Comma-separated service names from `ip-ranges.json`, e.g. `S3,API_GATEWAY` |
| `awsRegion`             | no       | Lambda's `AWS_REGION`                            | Region of the security groups, table and parameter       |
| `amazonIPRangesURL`     | no       | `https://ip-ranges.amazonaws.com/ip-ranges.json` | Source of the IP ranges                                  |
| `dynamoTableName`       | no       | `whitelistedIPRanges`                            | DynamoDB audit table (created if missing)                |
| `previousDateParamStore`| no       | `lastModifiedDateIPRanges`                       | SSM parameter holding the last processed `createDate` (created if missing) |
| `egressPort`            | no       | `443`                                            | TCP port allowed by the egress rules                     |
| `maxRulesPerGroup`      | no       | `50`                                             | Max egress rules per security group (match your [VPC quota](https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html#vpc-limits-security-groups)) |

Service names are case-insensitive. Available values include `AMAZON`, `S3`, `EC2`,
`CLOUDFRONT`, `DYNAMODB`, `API_GATEWAY`, `ROUTE53_HEALTHCHECKS`, `CODEBUILD`; see the
[documentation](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html) for the full list.

If the configured groups do not have enough free rule slots, the run fails with a
message stating how many are needed — add another security group to `securityGroupIDs`.

## Build

Requires Go (version in [`go.mod`](go.mod)), `make` and `zip`.

```sh
make package   # -> dist/whitelist-aws-ips.zip (linux/arm64)
make test      # unit tests with race detector
make help      # list all targets
```

For x86_64 Lambdas use `make package GOARCH=amd64`.

## Deploy

1. Create an execution role with the [IAM policy](#iam-policy) below plus the
   `AWSLambdaBasicExecutionRole` managed policy for CloudWatch Logs.

2. Create the function (custom runtime, `provided.al2023`):

   ```sh
   aws lambda create-function \
     --function-name whitelist-aws-ips \
     --runtime provided.al2023 \
     --architectures arm64 \
     --handler bootstrap \
     --timeout 120 \
     --memory-size 256 \
     --zip-file fileb://dist/whitelist-aws-ips.zip \
     --role arn:aws:iam::123456789012:role/whitelist-aws-ips \
     --environment 'Variables={securityGroupIDs=sg-0123456789abcdef0,servicesToBeWhitelist=S3}'
   ```

   To update the code later:

   ```sh
   aws lambda update-function-code --function-name whitelist-aws-ips \
     --zip-file fileb://dist/whitelist-aws-ips.zip
   ```

3. Schedule it with EventBridge, e.g. hourly:

   ```sh
   aws scheduler create-schedule \
     --name whitelist-aws-ips-hourly \
     --schedule-expression 'rate(1 hour)' \
     --flexible-time-window Mode=OFF \
     --target 'Arn=arn:aws:lambda:eu-central-1:123456789012:function:whitelist-aws-ips,RoleArn=arn:aws:iam::123456789012:role/scheduler-invoke-whitelist-aws-ips'
   ```

   Alternatively, subscribe the function to the `AmazonIpSpaceChanged` SNS topic
   (`arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged`) to run only when AWS publishes a change.

### IAM policy

Least-privilege policy; replace region, account ID and resource names as needed.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeSecurityGroups",
      "Effect": "Allow",
      "Action": "ec2:DescribeSecurityGroups",
      "Resource": "*"
    },
    {
      "Sid": "UpdateEgressRules",
      "Effect": "Allow",
      "Action": "ec2:AuthorizeSecurityGroupEgress",
      "Resource": [
        "arn:aws:ec2:eu-central-1:123456789012:security-group/sg-0123456789abcdef0"
      ]
    },
    {
      "Sid": "LastProcessedDate",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:PutParameter"],
      "Resource": "arn:aws:ssm:eu-central-1:123456789012:parameter/lastModifiedDateIPRanges"
    },
    {
      "Sid": "AuditTable",
      "Effect": "Allow",
      "Action": ["dynamodb:DescribeTable", "dynamodb:CreateTable", "dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:eu-central-1:123456789012:table/whitelistedIPRanges"
    }
  ]
}
```

`dynamodb:CreateTable` can be dropped if you create the table yourself
(partition key `awsIPRanges`, type `String`).

## Output

Logs are structured JSON (CloudWatch Logs Insights friendly):

```json
{"time":"2026-10-08T13:00:01Z","level":"INFO","msg":"resolved ip ranges","services":["S3"],"count":10,"createDate":"2026-10-08-11-03-09"}
{"time":"2026-10-08T13:00:01Z","level":"INFO","msg":"ip ranges changed","previous":"2026-10-01-20-13-04","current":"2026-10-08-11-03-09"}
{"time":"2026-10-08T13:00:02Z","level":"INFO","msg":"whitelisted ip ranges","securityGroup":"sg-0123456789abcdef0","cidrs":["52.218.0.0/16"]}
```

The function returns a summary of the run:

```json
{
  "createDate": "2026-10-08-11-03-09",
  "skipped": false,
  "desiredRanges": 10,
  "added": [{ "groupId": "sg-0123456789abcdef0", "cidrs": ["52.218.0.0/16"] }]
}
```

## Troubleshooting

| Error | Cause |
|-------|-------|
| `invalid configuration: ...` | A required variable is missing or malformed; the message lists every problem. |
| `AccessDeniedException` / `UnauthorizedOperation` | The execution role lacks a permission from the [IAM policy](#iam-policy). Also check permission boundaries and SCPs. |
| `not enough free rule slots ... need N, have M` | Add another security group, or raise `maxRulesPerGroup` if your VPC quota allows. |
| `no IP ranges found for services [...]` | The service names don't exist in `ip-ranges.json`. |

## Project layout

```
cmd/whitelist-aws-ips/    Lambda entry point and wiring
internal/config/          Environment configuration and validation
internal/ipranges/        Download and summarise ip-ranges.json
internal/securitygroup/   Capacity-aware, idempotent egress rule management
internal/store/           SSM parameter and DynamoDB audit table
internal/whitelist/       Run orchestration
```

## Changelog

See [Changelog.md](Changelog.md).
