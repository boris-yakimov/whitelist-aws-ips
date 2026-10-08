# Changelog

## v2.0.0

Rewrite focused on correctness, maintainability and deployability.

### Changed
- Migrated to AWS SDK for Go v2 and the `provided.al2023` runtime (`go1.x` is deprecated).
  The handler is now `bootstrap`, built for `arm64` by default.
- Split the code into packages under `internal/` with interfaces for all AWS clients.
- AWS clients are created once per cold start instead of per call.
- Security groups are now the source of truth: current egress rules are read and only
  missing CIDRs are added. DynamoDB is an audit log (`awsIPRanges`, `securityGroupId`, `createdAt`).
- CIDRs are added in a single API call per security group, each with a rule description.
- Structured JSON logging (`log/slog`); the handler returns a JSON run summary.
- Configuration is validated up front; only `securityGroupIDs` and
  `servicesToBeWhitelist` are required, everything else has defaults.
- New optional settings `egressPort` and `maxRulesPerGroup`.
- Makefile, CI (format, vet, race-enabled tests, golangci-lint, package artifact).

### Fixed
- `createDate` was saved before the security groups were updated, so a failed run was never retried.
- `setParamStoreValue` errors were ignored.
- Missing SSM parameter caused a failure on the first run; it is now created.
- `PutItem` and `AuthorizeSecurityGroupEgress` errors were printed but swallowed.
- Security group capacity check required an exact group count and ignored existing rules;
  it now checks free slots across all groups before making changes.
- Rule distribution could add the same CIDRs to multiple groups.
- Newly created DynamoDB table was used before becoming `ACTIVE`.
- DynamoDB presence check relied on a regex over a debug string.
- `describeSecurityGroups` called `os.Exit` from inside the Lambda.
- HTTP status codes of the IP ranges download were not checked.
- Duplicate and overlapping CIDRs (e.g. a `/22` inside a `/8`) are collapsed.

## v1.1
- Decode JSON directly from the URL without a temporary file.
- Configuration via Lambda environment variables.
- Go modules and GitHub Actions CI.

## v1.0
- Initial release: download AWS IP ranges, update security group egress rules,
  track state in SSM Parameter Store and DynamoDB.
