package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct {
	values map[string]string
	getErr error
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.values[aws.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.values[aws.ToString(in.Name)] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func TestParam(t *testing.T) {
	ctx := context.Background()
	p := NewParam(&fakeSSM{values: map[string]string{}}, "last")

	v, err := p.Get(ctx)
	if err != nil || v != "" {
		t.Fatalf("missing parameter should yield empty value, got %q, %v", v, err)
	}
	if err := p.Set(ctx, "2026-10-01"); err != nil {
		t.Fatal(err)
	}
	if v, _ := p.Get(ctx); v != "2026-10-01" {
		t.Errorf("Get = %q after Set", v)
	}
}

func TestParamGetError(t *testing.T) {
	p := NewParam(&fakeSSM{getErr: errors.New("access denied")}, "last")
	if _, err := p.Get(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

type fakeDynamo struct {
	exists      bool
	describeErr error
	created     int
	items       []map[string]dbtypes.AttributeValue
}

func (f *fakeDynamo) DescribeTable(_ context.Context, _ *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if !f.exists {
		return nil, &dbtypes.ResourceNotFoundException{}
	}
	return &dynamodb.DescribeTableOutput{Table: &dbtypes.TableDescription{TableStatus: dbtypes.TableStatusActive}}, nil
}

func (f *fakeDynamo) CreateTable(_ context.Context, in *dynamodb.CreateTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
	if in.BillingMode != dbtypes.BillingModePayPerRequest || aws.ToString(in.KeySchema[0].AttributeName) != attrCIDR {
		return nil, errors.New("unexpected table definition")
	}
	f.created++
	f.exists = true
	return &dynamodb.CreateTableOutput{}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.items = append(f.items, in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func TestTableEnsure(t *testing.T) {
	ctx := context.Background()

	existing := &fakeDynamo{exists: true}
	if err := NewTable(existing, "t").Ensure(ctx); err != nil || existing.created != 0 {
		t.Fatalf("existing table: err=%v created=%d", err, existing.created)
	}

	missing := &fakeDynamo{}
	if err := NewTable(missing, "t").Ensure(ctx); err != nil || missing.created != 1 {
		t.Fatalf("missing table: err=%v created=%d", err, missing.created)
	}

	broken := &fakeDynamo{describeErr: errors.New("throttled")}
	if err := NewTable(broken, "t").Ensure(ctx); err == nil {
		t.Fatal("expected describe error to propagate")
	}
}

func TestTableRecord(t *testing.T) {
	api := &fakeDynamo{exists: true}
	tbl := NewTable(api, "t")
	tbl.now = func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }

	if err := tbl.Record(context.Background(), "3.5.0.0/16", "sg-a"); err != nil {
		t.Fatal(err)
	}
	if len(api.items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(api.items))
	}
	item := api.items[0]
	for attr, want := range map[string]string{attrCIDR: "3.5.0.0/16", attrGroupID: "sg-a", attrCreatedAt: "2026-10-08T12:00:00Z"} {
		got, ok := item[attr].(*dbtypes.AttributeValueMemberS)
		if !ok || got.Value != want {
			t.Errorf("%s = %v, want %q", attr, item[attr], want)
		}
	}
}
