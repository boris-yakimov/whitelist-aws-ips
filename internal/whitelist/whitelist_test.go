package whitelist

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/burizz/whitelist-aws-ips/internal/ipranges"
	"github.com/burizz/whitelist-aws-ips/internal/securitygroup"
)

type memState struct {
	value  string
	setErr error
	sets   int
}

func (m *memState) Get(context.Context) (string, error) { return m.value, nil }
func (m *memState) Set(_ context.Context, v string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.sets++
	m.value = v
	return nil
}

type fakeGroups struct {
	calls  int
	cidrs  []string
	result []securitygroup.Assignment
	err    error
}

func (f *fakeGroups) Apply(_ context.Context, _ []string, cidrs []string) ([]securitygroup.Assignment, error) {
	f.calls++
	f.cidrs = cidrs
	return f.result, f.err
}

type fakeRecorder struct {
	ensured  int
	recorded map[string]string
}

func (f *fakeRecorder) Ensure(context.Context) error { f.ensured++; return nil }
func (f *fakeRecorder) Record(_ context.Context, cidr, groupID string) error {
	if f.recorded == nil {
		f.recorded = map[string]string{}
	}
	f.recorded[cidr] = groupID
	return nil
}

var doc = &ipranges.Document{
	CreateDate: "2026-10-01-12-00-00",
	Prefixes: []ipranges.Prefix{
		{IPPrefix: "3.5.140.0/22", Service: "S3"},
		{IPPrefix: "3.5.0.0/19", Service: "S3"},
		{IPPrefix: "52.95.0.0/16", Service: "AMAZON"},
	},
}

func newRunner(state *memState, groups *fakeGroups, rec *fakeRecorder) *Runner {
	return &Runner{
		Fetch:            func(context.Context) (*ipranges.Document, error) { return doc, nil },
		State:            state,
		Groups:           groups,
		Recorder:         rec,
		Services:         []string{"S3"},
		SecurityGroupIDs: []string{"sg-a"},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestRunSkipsWhenUnchanged(t *testing.T) {
	state := &memState{value: doc.CreateDate}
	groups := &fakeGroups{}
	res, err := newRunner(state, groups, &fakeRecorder{}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || groups.calls != 0 {
		t.Errorf("expected skipped run, got %+v (apply calls %d)", res, groups.calls)
	}
}

func TestRunAppliesAndRecords(t *testing.T) {
	state := &memState{}
	groups := &fakeGroups{result: []securitygroup.Assignment{{GroupID: "sg-a", CIDRs: []string{"3.5.0.0/16"}}}}
	rec := &fakeRecorder{}

	res, err := newRunner(state, groups, rec).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups.cidrs) != 1 || groups.cidrs[0] != "3.5.0.0/16" {
		t.Errorf("unexpected desired CIDRs: %v", groups.cidrs)
	}
	if rec.ensured != 1 || rec.recorded["3.5.0.0/16"] != "sg-a" {
		t.Errorf("audit not recorded: %+v", rec)
	}
	if state.value != doc.CreateDate || res.Skipped || res.Desired != 1 || len(res.Added) != 1 {
		t.Errorf("unexpected result %+v / state %q", res, state.value)
	}
}

func TestRunDoesNotSaveDateOnFailure(t *testing.T) {
	state := &memState{value: "old"}
	groups := &fakeGroups{
		result: []securitygroup.Assignment{{GroupID: "sg-a", CIDRs: []string{"3.5.0.0/16"}}},
		err:    errors.New("authorize failed"),
	}
	rec := &fakeRecorder{}

	if _, err := newRunner(state, groups, rec).Run(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if state.value != "old" || state.sets != 0 {
		t.Errorf("date must not be saved after a failed update, got %q", state.value)
	}
	if rec.recorded["3.5.0.0/16"] != "sg-a" {
		t.Error("partially applied CIDRs should still be recorded")
	}
}

func TestRunNoMatchingRanges(t *testing.T) {
	r := newRunner(&memState{}, &fakeGroups{}, &fakeRecorder{})
	r.Services = []string{"UNKNOWN"}
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("expected error when no ranges match")
	}
}

func TestRunFetchError(t *testing.T) {
	r := newRunner(&memState{}, &fakeGroups{}, &fakeRecorder{})
	r.Fetch = func(context.Context) (*ipranges.Document, error) { return nil, errors.New("offline") }
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
