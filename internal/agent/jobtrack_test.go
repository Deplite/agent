package agent

import (
	"context"
	"encoding/json"
	"testing"
)

func TestJobTrackerCancelQueued(t *testing.T) {
	tr := newJobTracker()
	tr.queue("j1")
	found, running := tr.cancel("j1")
	if !found || running {
		t.Fatalf("found=%v running=%v, want found without running", found, running)
	}
	if !tr.isCanceled("j1") {
		t.Fatal("queued job should be flagged canceled")
	}
}

func TestJobTrackerCancelRunning(t *testing.T) {
	tr := newJobTracker()
	tr.queue("j1")
	ctx, cancel, already := tr.running(context.Background(), "j1")
	defer cancel()
	if already {
		t.Fatal("job should not start canceled")
	}
	found, running := tr.cancel("j1")
	if !found || !running {
		t.Fatalf("found=%v running=%v, want both", found, running)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("running job context should be canceled")
	}
}

func TestJobTrackerCancelBeforeRunHonored(t *testing.T) {
	tr := newJobTracker()
	tr.queue("j1")
	tr.cancel("j1")
	ctx, cancel, already := tr.running(context.Background(), "j1")
	defer cancel()
	if !already {
		t.Fatal("running should report the queued cancel")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("context should already be canceled")
	}
}

func TestJobTrackerFinishForgets(t *testing.T) {
	tr := newJobTracker()
	if found, _ := tr.cancel("nope"); found {
		t.Fatal("unknown job should not be found")
	}
	tr.queue("j2")
	tr.finish("j2")
	if found, _ := tr.cancel("j2"); found {
		t.Fatal("finished job should be forgotten")
	}
}

func TestCancelPayloadReason(t *testing.T) {
	var user cancelPayload
	if err := json.Unmarshal([]byte(`{"job_id":"j","reason":null,"actor":"u1"}`), &user); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if user.reasonText() != "" {
		t.Fatalf("null reason should be empty, got %q", user.reasonText())
	}
	if user.Actor != "u1" || user.Superseded {
		t.Fatalf("unexpected: %+v", user)
	}

	var sup cancelPayload
	if err := json.Unmarshal([]byte(`{"job_id":"j","reason":"superseded by release 1.3.0","superseded":true}`), &sup); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !sup.Superseded || sup.reasonText() != "superseded by release 1.3.0" {
		t.Fatalf("unexpected: %+v", sup)
	}
}
