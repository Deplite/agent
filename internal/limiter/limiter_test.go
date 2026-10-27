package limiter

import (
	"testing"
	"time"

	"github.com/Deplite/agent/internal/workflow"
)

func newWorkflow(t *testing.T, limits []workflow.Limit) *workflow.Workflow {
	t.Helper()
	wf := &workflow.Workflow{
		Name:   "wf-limits",
		Steps:  []workflow.Step{{Name: "s", Run: "true"}},
		Limits: limits,
	}
	if err := wf.Validate(); err != nil {
		t.Fatalf("validate workflow: %v", err)
	}
	return wf
}

func mustAcquire(t *testing.T, m *Manager, wf *workflow.Workflow, now time.Time) {
	t.Helper()
	dec, err := m.TryAcquire(wf, now)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("TryAcquire denied: %+v", dec)
	}
}

func mustDeny(t *testing.T, m *Manager, wf *workflow.Workflow, now time.Time, limitType string) Decision {
	t.Helper()
	dec, err := m.TryAcquire(wf, now)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if dec.Allowed {
		t.Fatal("TryAcquire allowed, want denied")
	}
	if dec.LimitType != limitType {
		t.Fatalf("LimitType = %q, want %q", dec.LimitType, limitType)
	}
	return dec
}

func TestNoLimitsAlwaysAllowed(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, nil)
	mustAcquire(t, m, wf, time.Now())
	if err := m.Release(wf, time.Now(), "success"); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestCooldownBlocksAfterSuccess(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitCooldown, After: "1m"}})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	if err := m.Release(wf, t0, "success"); err != nil {
		t.Fatalf("Release: %v", err)
	}

	dec := mustDeny(t, m, wf, t0.Add(30*time.Second), "cooldown")
	if dec.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", dec.RetryAfter)
	}

	mustAcquire(t, m, wf, t0.Add(61*time.Second))
}

func TestCooldownDefaultIgnoresFailedRuns(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitCooldown, After: "1m"}})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	if err := m.Release(wf, t0, "failed"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mustAcquire(t, m, wf, t0.Add(time.Second))
}

func TestCooldownOnAnyBlocksAfterFailure(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitCooldown, After: "1m", On: "any"}})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	if err := m.Release(wf, t0, "failed"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mustDeny(t, m, wf, t0.Add(time.Second), "cooldown")
}

func TestBucketDepletesAndRefills(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitBucket, Capacity: 2, Refill: "1/1m"}})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	mustAcquire(t, m, wf, t0)

	dec := mustDeny(t, m, wf, t0, "bucket")
	if dec.RetryAfter != time.Minute {
		t.Errorf("RetryAfter = %v, want 1m", dec.RetryAfter)
	}

	mustAcquire(t, m, wf, t0.Add(time.Minute))
	mustDeny(t, m, wf, t0.Add(time.Minute), "bucket")
}

func TestBucketNeverExceedsCapacity(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitBucket, Capacity: 1, Refill: "1/1m"}})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	mustAcquire(t, m, wf, t0.Add(time.Hour))
	mustDeny(t, m, wf, t0.Add(time.Hour), "bucket")
}

func TestStatePersistsAcrossManagers(t *testing.T) {
	dir := t.TempDir()
	wf := newWorkflow(t, []workflow.Limit{{Type: workflow.LimitBucket, Capacity: 1, Refill: "1/1m"}})
	t0 := time.Now()

	mustAcquire(t, New(dir), wf, t0)
	mustDeny(t, New(dir), wf, t0, "bucket")
}

func TestCombinedLimitsReportSlowestRetry(t *testing.T) {
	m := New(t.TempDir())
	wf := newWorkflow(t, []workflow.Limit{
		{Type: workflow.LimitCooldown, After: "10m", On: "any"},
		{Type: workflow.LimitBucket, Capacity: 1, Refill: "1/1m"},
	})
	t0 := time.Now()

	mustAcquire(t, m, wf, t0)
	if err := m.Release(wf, t0, "failed"); err != nil {
		t.Fatalf("Release: %v", err)
	}

	dec := mustDeny(t, m, wf, t0.Add(time.Second), "cooldown")
	if dec.RetryAfter < 9*time.Minute {
		t.Errorf("RetryAfter = %v, want the cooldown's (worst) retry", dec.RetryAfter)
	}
}

func TestBypassTypes(t *testing.T) {
	wf := newWorkflow(t, []workflow.Limit{
		{Type: workflow.LimitCooldown, After: "1m"},
		{Type: workflow.LimitBucket, Capacity: 1, Refill: "1/1m"},
	})
	got := BypassTypes(wf)
	if len(got) != 2 || got[0] != "cooldown" || got[1] != "bucket" {
		t.Errorf("BypassTypes = %v, want [cooldown bucket]", got)
	}
}
