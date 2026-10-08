// Package securitygroup manages the egress rules of the target EC2 security
// groups, spreading CIDRs across groups to stay within the per-group rule quota.
package securitygroup

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// RuleDescription is attached to every rule created by this tool so managed
// rules can be identified in the console.
const RuleDescription = "Managed by whitelist-aws-ips"

// ErrInsufficientCapacity is returned when the configured security groups
// cannot hold all CIDRs that need to be added.
var ErrInsufficientCapacity = errors.New("not enough free rule slots in the configured security groups")

// API is the subset of the EC2 client used by Manager.
type API interface {
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	AuthorizeSecurityGroupEgress(ctx context.Context, in *ec2.AuthorizeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
}

// Assignment records the CIDRs added to a single security group.
type Assignment struct {
	GroupID string   `json:"groupId"`
	CIDRs   []string `json:"cidrs"`
}

// Manager adds TCP egress rules for a single port.
type Manager struct {
	client   API
	port     int32
	maxRules int
}

// NewManager returns a Manager that creates tcp/port egress rules and allows
// at most maxRules egress rules per security group.
func NewManager(client API, port int32, maxRules int) *Manager {
	return &Manager{client: client, port: port, maxRules: maxRules}
}

type groupState struct {
	existing map[string]struct{} // CIDRs already allowed on our port
	used     int                 // total egress rules in the group
}

// Apply ensures every CIDR in cidrs is allowed by exactly one of groupIDs.
// The current state of the groups is read first, so CIDRs that already exist
// are skipped and the run is idempotent. Capacity is verified before any
// change is made. Groups are filled in the order given.
func (m *Manager) Apply(ctx context.Context, groupIDs, cidrs []string) ([]Assignment, error) {
	states, err := m.describe(ctx, groupIDs)
	if err != nil {
		return nil, err
	}

	var missing []string
	for _, cidr := range cidrs {
		if !anyContains(states, cidr) {
			missing = append(missing, cidr)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}

	free := 0
	for _, id := range groupIDs {
		free += max(0, m.maxRules-states[id].used)
	}
	if free < len(missing) {
		return nil, fmt.Errorf("%w: need %d, have %d (limit %d rules per group); add more security groups",
			ErrInsufficientCapacity, len(missing), free, m.maxRules)
	}

	var assignments []Assignment
	for _, id := range groupIDs {
		if len(missing) == 0 {
			break
		}
		n := min(m.maxRules-states[id].used, len(missing))
		if n <= 0 {
			continue
		}
		batch := missing[:n]
		missing = missing[n:]

		if err := m.authorize(ctx, id, batch); err != nil {
			return assignments, err
		}
		assignments = append(assignments, Assignment{GroupID: id, CIDRs: batch})
	}
	return assignments, nil
}

func (m *Manager) describe(ctx context.Context, groupIDs []string) (map[string]*groupState, error) {
	out, err := m.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: groupIDs})
	if err != nil {
		return nil, fmt.Errorf("describe security groups: %w", err)
	}

	states := make(map[string]*groupState, len(groupIDs))
	for _, sg := range out.SecurityGroups {
		st := &groupState{existing: make(map[string]struct{})}
		for _, perm := range sg.IpPermissionsEgress {
			st.used += len(perm.IpRanges) + len(perm.Ipv6Ranges) + len(perm.PrefixListIds) + len(perm.UserIdGroupPairs)
			if !m.matchesRule(perm) {
				continue
			}
			for _, r := range perm.IpRanges {
				st.existing[aws.ToString(r.CidrIp)] = struct{}{}
			}
		}
		states[aws.ToString(sg.GroupId)] = st
	}

	for _, id := range groupIDs {
		if _, ok := states[id]; !ok {
			return nil, fmt.Errorf("describe security groups: %s not found", id)
		}
	}
	return states, nil
}

func (m *Manager) matchesRule(p types.IpPermission) bool {
	return aws.ToString(p.IpProtocol) == "tcp" &&
		aws.ToInt32(p.FromPort) == m.port &&
		aws.ToInt32(p.ToPort) == m.port
}

func (m *Manager) authorize(ctx context.Context, groupID string, cidrs []string) error {
	ranges := make([]types.IpRange, 0, len(cidrs))
	for _, c := range cidrs {
		ranges = append(ranges, types.IpRange{CidrIp: aws.String(c), Description: aws.String(RuleDescription)})
	}

	_, err := m.client.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(m.port),
			ToPort:     aws.Int32(m.port),
			IpRanges:   ranges,
		}},
	})
	if err != nil {
		return fmt.Errorf("authorize egress on %s: %w", groupID, err)
	}
	return nil
}

func anyContains(states map[string]*groupState, cidr string) bool {
	for _, st := range states {
		if _, ok := st.existing[cidr]; ok {
			return true
		}
	}
	return false
}
