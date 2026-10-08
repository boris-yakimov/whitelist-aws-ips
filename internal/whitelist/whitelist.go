// Package whitelist orchestrates a single whitelisting run.
package whitelist

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/burizz/whitelist-aws-ips/internal/ipranges"
	"github.com/burizz/whitelist-aws-ips/internal/securitygroup"
)

// SupernetBits is the prefix length individual AWS ranges are widened to,
// which keeps the number of security group rules manageable.
const SupernetBits = 16

// Fetcher retrieves the current AWS IP ranges document.
type Fetcher func(ctx context.Context) (*ipranges.Document, error)

// StateStore persists the createDate of the last fully processed document.
type StateStore interface {
	Get(ctx context.Context) (string, error)
	Set(ctx context.Context, value string) error
}

// GroupApplier ensures CIDRs are present in the security groups.
type GroupApplier interface {
	Apply(ctx context.Context, groupIDs, cidrs []string) ([]securitygroup.Assignment, error)
}

// Recorder keeps an audit trail of whitelisted CIDRs.
type Recorder interface {
	Ensure(ctx context.Context) error
	Record(ctx context.Context, cidr, groupID string) error
}

// Runner wires the dependencies of a run together.
type Runner struct {
	Fetch            Fetcher
	State            StateStore
	Groups           GroupApplier
	Recorder         Recorder
	Services         []string
	SecurityGroupIDs []string
	Logger           *slog.Logger
}

// Result summarises the outcome of a run; it is returned as the Lambda response.
type Result struct {
	CreateDate string                     `json:"createDate"`
	Skipped    bool                       `json:"skipped"`
	Desired    int                        `json:"desiredRanges"`
	Added      []securitygroup.Assignment `json:"added,omitempty"`
}

// Run executes one whitelisting pass. The processed createDate is persisted
// only after the security groups were updated successfully, so a failed run
// is retried in full on the next invocation.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	log := r.Logger
	if log == nil {
		log = slog.Default()
	}

	doc, err := r.Fetch(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("fetch ip ranges: %w", err)
	}
	res := Result{CreateDate: doc.CreateDate}

	prefixes, err := ipranges.Summarize(doc, r.Services, SupernetBits)
	if err != nil {
		return res, fmt.Errorf("summarize ip ranges: %w", err)
	}
	if len(prefixes) == 0 {
		return res, fmt.Errorf("no IP ranges found for services %v", r.Services)
	}
	res.Desired = len(prefixes)
	log.Info("resolved ip ranges", "services", r.Services, "count", len(prefixes), "createDate", doc.CreateDate)

	last, err := r.State.Get(ctx)
	if err != nil {
		return res, fmt.Errorf("read last processed date: %w", err)
	}
	if last == doc.CreateDate {
		log.Info("ip ranges unchanged since last run, nothing to do", "createDate", last)
		res.Skipped = true
		return res, nil
	}
	log.Info("ip ranges changed", "previous", last, "current", doc.CreateDate)

	if err := r.Recorder.Ensure(ctx); err != nil {
		return res, fmt.Errorf("prepare audit table: %w", err)
	}

	cidrs := make([]string, len(prefixes))
	for i, p := range prefixes {
		cidrs[i] = p.String()
	}

	added, err := r.Groups.Apply(ctx, r.SecurityGroupIDs, cidrs)
	res.Added = added
	// Record whatever was applied, even on partial failure, so the audit trail
	// matches reality.
	if recErr := r.record(ctx, added); recErr != nil && err == nil {
		err = recErr
	}
	if err != nil {
		return res, fmt.Errorf("update security groups: %w", err)
	}

	for _, a := range added {
		log.Info("whitelisted ip ranges", "securityGroup", a.GroupID, "cidrs", a.CIDRs)
	}
	if len(added) == 0 {
		log.Info("all ip ranges already whitelisted")
	}

	if err := r.State.Set(ctx, doc.CreateDate); err != nil {
		return res, fmt.Errorf("save last processed date: %w", err)
	}
	return res, nil
}

func (r *Runner) record(ctx context.Context, added []securitygroup.Assignment) error {
	for _, a := range added {
		for _, cidr := range a.CIDRs {
			if err := r.Recorder.Record(ctx, cidr, a.GroupID); err != nil {
				return fmt.Errorf("record %s: %w", cidr, err)
			}
		}
	}
	return nil
}
