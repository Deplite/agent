package limiter

import (
	"testing"
	"time"

	"github.com/Deplite/agent/internal/workflow"
)

func limitedWorkflow(t *testing.T) *workflow.Workflow {
	t.Helper()
	wf := &workflow.Workflow{
		Name:   "limited",
		Steps:  []workflow.Step{{Name: "noop", Run: "true"}},
		Limits: []workflow.Limit{{Type: workflow.LimitCooldown, After: "10m"}, {Type: workflow.LimitBucket, Capacity: 2, Refill: "1/1h"}},
	}
	if err := wf.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return wf
}

// Inspect is what `deplite-agent limits` reads, so it must report the
// same standing TryAcquire would enforce without consuming a token.
func TestInspectDoesNotConsume(t *testing.T) {
	m := New(t.TempDir())
	wf := limitedWorkflow(t)
	now := time.Now()

	before, err := m.Inspect(wf, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 {
		t.Fatalf("got %d statuses, want 2", len(before))
	}
	if before[1].Tokens != 2 {
		t.Errorf("bucket tokens = %v, want 2", before[1].Tokens)
	}

	after, err := m.Inspect(wf, now)
	if err != nil {
		t.Fatal(err)
	}
	if after[1].Tokens != before[1].Tokens {
		t.Errorf("tokens changed to %v after a read-only inspect", after[1].Tokens)
	}

	if _, err := m.TryAcquire(wf, now); err != nil {
		t.Fatal(err)
	}
	spent, err := m.Inspect(wf, now)
	if err != nil {
		t.Fatal(err)
	}
	if spent[1].Tokens != 1 {
		t.Errorf("tokens = %v after one acquire, want 1", spent[1].Tokens)
	}
}

func TestInspectReportsCooldownWait(t *testing.T) {
	m := New(t.TempDir())
	wf := limitedWorkflow(t)
	now := time.Now()

	if err := m.Release(wf, now, "success"); err != nil {
		t.Fatal(err)
	}
	statuses, err := m.Inspect(wf, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0].Allowed {
		t.Fatal("cooldown reported as allowed one minute after a success")
	}
	if got := statuses[0].RetryAfter.Round(time.Minute); got != 9*time.Minute {
		t.Errorf("retry after = %s, want about 9m", got)
	}
	if statuses[0].LastStatus != "success" {
		t.Errorf("last status = %q, want success", statuses[0].LastStatus)
	}
}

func TestResetClearsState(t *testing.T) {
	m := New(t.TempDir())
	wf := limitedWorkflow(t)
	now := time.Now()

	if err := m.Release(wf, now, "success"); err != nil {
		t.Fatal(err)
	}
	if err := m.Reset(wf.Name); err != nil {
		t.Fatal(err)
	}
	statuses, err := m.Inspect(wf, now)
	if err != nil {
		t.Fatal(err)
	}
	if !statuses[0].Allowed {
		t.Error("cooldown still blocking after reset")
	}
	// Resetting a workflow that never ran is not an error.
	if err := m.Reset("never-ran"); err != nil {
		t.Errorf("reset of an unused workflow: %v", err)
	}
}

func TestResetRejectsPathLikeNames(t *testing.T) {
	m := New(t.TempDir())
	for _, name := range []string{"", ".", "..", "a/b", "../escape"} {
		if err := m.Reset(name); err == nil {
			t.Errorf("Reset(%q) was accepted", name)
		}
	}
}
