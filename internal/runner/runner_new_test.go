package runner

import (
	"context"
	"runtime"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/joblog"
	"github.com/Deplite/agent/internal/mask"
	"github.com/Deplite/agent/internal/workflow"
)

func TestRunValidatesParams(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name: "p",
		Params: []workflow.Param{
			{Name: "tag", Type: workflow.ParamString, Required: true, Pattern: "^v[0-9]+$"},
		},
		Steps: []workflow.Step{{Name: "ok", Run: "true"}},
	}

	bad := Run(context.Background(), wf, "j", map[string]any{"tag": "nope"}, nil, shipper, mask.New(), false)
	if bad.Status != apiclient.JobFailed {
		t.Fatalf("expected failed, got %+v", bad)
	}

	ok := Run(context.Background(), wf, "j", map[string]any{"tag": "v1"}, nil, shipper, mask.New(), false)
	if ok.Status != apiclient.JobSuccess {
		t.Fatalf("expected success, got %+v", ok)
	}
}

func TestRunCapturesOutputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name: "out",
		Outputs: []workflow.Output{
			{Name: "sha", Type: workflow.OutputString, From: "build.commit"},
			{Name: "count", Type: workflow.OutputNumber, From: "build.n"},
		},
		Steps: []workflow.Step{
			{ID: "build", Name: "b", Run: `printf "commit=abc123\nn=42\n" > "$DEPLITE_OUTPUT"`},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	if res.Outputs["sha"] != "abc123" {
		t.Fatalf("sha output = %v", res.Outputs["sha"])
	}
	if n, ok := res.Outputs["count"].(float64); !ok || n != 42 {
		t.Fatalf("count output = %v (%T)", res.Outputs["count"], res.Outputs["count"])
	}
}

func TestRunRetriesUntilSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	dir := t.TempDir()
	wf := workflow.Workflow{
		Name: "retry",
		Steps: []workflow.Step{
			{
				Name: "flaky",
				Run: `f=` + dir + `/n
n=$(cat "$f" 2>/dev/null || echo 0)
n=$((n+1))
echo $n > "$f"
if [ "$n" -lt 3 ]; then exit 1; fi
echo done`,
				Retry: &workflow.Retry{MaxAttempts: 5, InitialDelaySeconds: 0},
			},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
}

func TestRunRetryExhausts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name: "retry2",
		Steps: []workflow.Step{
			{Name: "always-fails", Run: "exit 9", Retry: &workflow.Retry{MaxAttempts: 2, InitialDelaySeconds: 0}},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobFailed || res.ExitCode != 9 {
		t.Fatalf("got %+v", res)
	}
}

func TestRunFailsOnMissingRequiredSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name: "sec",
		Secrets: []workflow.Secret{
			{Name: "GH_TOKEN", Required: true},
		},
		Steps: []workflow.Step{{Name: "x", Run: "true"}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobFailed {
		t.Fatalf("expected failed without required secret, got %+v", res)
	}
}

func TestRunSecretScopeHidesFromOtherSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "scope",
		Secrets: []workflow.Secret{
			{Name: "SCOPED", Required: true, Scope: []string{"allowed"}},
		},
		Steps: []workflow.Step{
			{ID: "allowed", Name: "in-scope", Run: `echo "in=$DEPLITE_SECRET_SCOPED"`, Verbose: true},
			{ID: "blocked", Name: "out-of-scope", Run: `echo "out=${DEPLITE_SECRET_SCOPED:-none}"`, Verbose: true},
		},
	}
	res := Run(context.Background(), wf, "j", nil, map[string]string{"SCOPED": "shh"}, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	sawIn, sawOut := false, false
	for _, it := range sink.items {
		if it.Stream != apiclient.LogStreamRaw {
			continue
		}
		if it.Content == "in=[REDACTED]" {
			sawIn = true
		}
		if it.Content == "out=none" {
			sawOut = true
		}
	}
	if !sawIn {
		t.Fatalf("scoped step should see masked secret; got %+v", sink.items)
	}
	if !sawOut {
		t.Fatalf("non-scoped step should not see secret; got %+v", sink.items)
	}
}
