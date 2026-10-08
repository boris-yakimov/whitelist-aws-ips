package securitygroup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeEC2 is an in-memory EC2 implementation keyed by group ID.
type fakeEC2 struct {
	groups       map[string][]types.IpPermission
	authorizeErr error
	calls        int
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	out := &ec2.DescribeSecurityGroupsOutput{}
	for _, id := range in.GroupIds {
		if perms, ok := f.groups[id]; ok {
			out.SecurityGroups = append(out.SecurityGroups, types.SecurityGroup{GroupId: aws.String(id), IpPermissionsEgress: perms})
		}
	}
	return out, nil
}

func (f *fakeEC2) AuthorizeSecurityGroupEgress(_ context.Context, in *ec2.AuthorizeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
	f.calls++
	if f.authorizeErr != nil {
		return nil, f.authorizeErr
	}
	id := aws.ToString(in.GroupId)
	f.groups[id] = append(f.groups[id], in.IpPermissions...)
	return &ec2.AuthorizeSecurityGroupEgressOutput{}, nil
}

func cidrs(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s.%d.0.0/16", prefix, i)
	}
	return out
}

func rule(proto string, port int32, cidrs ...string) types.IpPermission {
	p := types.IpPermission{IpProtocol: aws.String(proto), FromPort: aws.Int32(port), ToPort: aws.Int32(port)}
	for _, c := range cidrs {
		p.IpRanges = append(p.IpRanges, types.IpRange{CidrIp: aws.String(c)})
	}
	return p
}

func TestApplyDistributesAcrossGroups(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{"sg-a": nil, "sg-b": nil}}
	m := NewManager(api, 443, 3)

	got, err := m.Apply(context.Background(), []string{"sg-a", "sg-b"}, cidrs("10", 5))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(got) != 2 || got[0].GroupID != "sg-a" || len(got[0].CIDRs) != 3 || got[1].GroupID != "sg-b" || len(got[1].CIDRs) != 2 {
		t.Fatalf("unexpected assignments: %+v", got)
	}
	// Each CIDR is added exactly once, with a description.
	for _, perm := range api.groups["sg-a"] {
		for _, r := range perm.IpRanges {
			if aws.ToString(r.Description) != RuleDescription {
				t.Errorf("missing description on %s", aws.ToString(r.CidrIp))
			}
		}
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{"sg-a": nil}}
	m := NewManager(api, 443, 50)
	want := cidrs("10", 4)

	if _, err := m.Apply(context.Background(), []string{"sg-a"}, want); err != nil {
		t.Fatal(err)
	}
	got, err := m.Apply(context.Background(), []string{"sg-a"}, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || api.calls != 1 {
		t.Errorf("second Apply should be a no-op, got %+v after %d calls", got, api.calls)
	}
}

func TestApplySkipsExistingAndCountsOtherRules(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{
		// 10.0 already allowed on 443; 10.1 is allowed on a different port, so it
		// still needs a rule. Together they occupy 2 of 3 slots.
		"sg-a": {rule("tcp", 443, "10.0.0.0/16"), rule("tcp", 80, "10.1.0.0/16")},
		"sg-b": nil,
	}}
	m := NewManager(api, 443, 3)

	got, err := m.Apply(context.Background(), []string{"sg-a", "sg-b"}, cidrs("10", 3))
	if err != nil {
		t.Fatal(err)
	}
	want := []Assignment{{GroupID: "sg-a", CIDRs: []string{"10.1.0.0/16"}}, {GroupID: "sg-b", CIDRs: []string{"10.2.0.0/16"}}}
	if !slices.EqualFunc(got, want, func(a, b Assignment) bool { return a.GroupID == b.GroupID && slices.Equal(a.CIDRs, b.CIDRs) }) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestApplyInsufficientCapacity(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{"sg-a": {rule("-1", 0, "0.0.0.0/0")}}}
	m := NewManager(api, 443, 2)

	_, err := m.Apply(context.Background(), []string{"sg-a"}, cidrs("10", 2))
	if !errors.Is(err, ErrInsufficientCapacity) {
		t.Fatalf("expected ErrInsufficientCapacity, got %v", err)
	}
	if api.calls != 0 {
		t.Error("no changes must be made when capacity is insufficient")
	}
}

func TestApplyUnknownGroup(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{}}
	if _, err := NewManager(api, 443, 50).Apply(context.Background(), []string{"sg-missing"}, cidrs("10", 1)); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestApplyAuthorizeError(t *testing.T) {
	api := &fakeEC2{groups: map[string][]types.IpPermission{"sg-a": nil}, authorizeErr: errors.New("denied")}
	if _, err := NewManager(api, 443, 50).Apply(context.Background(), []string{"sg-a"}, cidrs("10", 1)); err == nil {
		t.Fatal("expected error")
	}
}
