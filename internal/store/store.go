// Package store persists run state: the last processed ip-ranges.json
// createDate (SSM Parameter Store) and an audit record of every whitelisted
// CIDR (DynamoDB).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ParamAPI is the subset of the SSM client used by Param.
type ParamAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// Param stores a single string value in SSM Parameter Store.
type Param struct {
	client ParamAPI
	name   string
}

// NewParam returns a Param backed by the SSM parameter called name.
func NewParam(client ParamAPI, name string) *Param {
	return &Param{client: client, name: name}
}

// Get returns the parameter value, or "" if the parameter does not exist yet.
func (p *Param) Get(ctx context.Context) (string, error) {
	out, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(p.name)})
	if err != nil {
		var notFound *ssmtypes.ParameterNotFound
		if errors.As(err, &notFound) {
			return "", nil
		}
		return "", fmt.Errorf("get parameter %s: %w", p.name, err)
	}
	return aws.ToString(out.Parameter.Value), nil
}

// Set creates or overwrites the parameter value.
func (p *Param) Set(ctx context.Context, value string) error {
	_, err := p.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(p.name),
		Value:     aws.String(value),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("put parameter %s: %w", p.name, err)
	}
	return nil
}

// Attribute names of the DynamoDB table. The partition key name is kept for
// compatibility with tables created by earlier versions.
const (
	attrCIDR      = "awsIPRanges"
	attrGroupID   = "securityGroupId"
	attrCreatedAt = "createdAt"
)

// TableAPI is the subset of the DynamoDB client used by Table.
type TableAPI interface {
	dynamodb.DescribeTableAPIClient
	CreateTable(ctx context.Context, in *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// Table records whitelisted CIDRs in DynamoDB.
type Table struct {
	client  TableAPI
	name    string
	maxWait time.Duration
	now     func() time.Time
}

// NewTable returns a Table backed by the DynamoDB table called name.
func NewTable(client TableAPI, name string) *Table {
	return &Table{client: client, name: name, maxWait: 2 * time.Minute, now: time.Now}
}

// Ensure creates the table (on-demand billing) if it does not exist and waits
// until it is ACTIVE.
func (t *Table) Ensure(ctx context.Context) error {
	_, err := t.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.name)})
	if err == nil {
		return nil
	}
	var notFound *dbtypes.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		return fmt.Errorf("describe table %s: %w", t.name, err)
	}

	_, err = t.client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(t.name),
		BillingMode:          dbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []dbtypes.AttributeDefinition{{AttributeName: aws.String(attrCIDR), AttributeType: dbtypes.ScalarAttributeTypeS}},
		KeySchema:            []dbtypes.KeySchemaElement{{AttributeName: aws.String(attrCIDR), KeyType: dbtypes.KeyTypeHash}},
	})
	var inUse *dbtypes.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		return fmt.Errorf("create table %s: %w", t.name, err)
	}

	waiter := dynamodb.NewTableExistsWaiter(t.client)
	if err := waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.name)}, t.maxWait); err != nil {
		return fmt.Errorf("wait for table %s: %w", t.name, err)
	}
	return nil
}

// Record stores that cidr has been whitelisted in security group groupID.
func (t *Table) Record(ctx context.Context, cidr, groupID string) error {
	_, err := t.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(t.name),
		Item: map[string]dbtypes.AttributeValue{
			attrCIDR:      &dbtypes.AttributeValueMemberS{Value: cidr},
			attrGroupID:   &dbtypes.AttributeValueMemberS{Value: groupID},
			attrCreatedAt: &dbtypes.AttributeValueMemberS{Value: t.now().UTC().Format(time.RFC3339)},
		},
	})
	if err != nil {
		return fmt.Errorf("put item %s into %s: %w", cidr, t.name, err)
	}
	return nil
}
