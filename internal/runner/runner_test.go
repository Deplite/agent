package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/joblog"
	"github.com/Deplite/agent/internal/mask"
	"github.com/Deplite/agent/internal/workflow"
)

type captureSink struct {
	items []apiclient.LogItem
}

func (c *captureSink) AppendJobLogs(_ context.Context, _ apiclient.Signer, _ string, items []apiclient.LogItem) (apiclient.LogsResponse, error) {
	c.items = append(c.items, items...)
	return apiclient.LogsResponse{Accepted: len(items)}, nil
}

type stubSigner struct{}

func (stubSigner) AgentID() string      { return "a" }
func (stubSigner) Sign(m []byte) []byte { return nil }

func TestRunSuccessfulWorkflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	masker := mask.New()

	wf := workflow.Workflow{
		Name: "demo",
		Steps: []workflow.Step{
			{Name: "say", Run: "echo hello"},
			{Name: "ok", Run: "true"},
		},
	}
	res := Run(context.Background(), wf, "job1", nil, nil, shipper, masker, false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s, error=%s", res.Status, res.Error)
	}
	if err := shipper.Flush(context.Background(), "job1"); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(sink.items) == 0 {
		t.Fatal("no log items captured")
	}
}

func TestRunFailsOnNonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name:  "fail",
		Steps: []workflow.Step{{Name: "boom", Run: "exit 7"}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobFailed || res.ExitCode != 7 {
		t.Fatalf("got %+v", res)
	}
}

func TestRunRespectsStepTimeoutMinutes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	// We can't set minutes < 1 via the workflow field, so use the
	// negative path by simulating a sub-minute step timeout through a
	// short context deadline.
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name:  "slow",
		Steps: []workflow.Step{{Name: "wait", Run: "sleep 10"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*1000000) // 500ms
	defer cancel()
	res := Run(ctx, wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobTimeout && res.Status != apiclient.JobFailed {
		t.Fatalf("got %+v", res)
	}
}

func TestMakeScratch(t *testing.T) {
	dir, err := makeScratch("job-1")
	if err != nil {
		t.Fatalf("makeScratch: %v", err)
	}
	defer os.RemoveAll(dir)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("scratch directory was not created: %q (%v)", dir, err)
	}
}

func TestRunHonorsWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	tmp := t.TempDir()
	// macOS resolves /var to /private/var, so compare against the
	// real path of the temp dir.
	want, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	wf := workflow.Workflow{
		Name: "wd",
		Steps: []workflow.Step{
			{Name: "pwd", WorkingDirectory: tmp, Run: `pwd`, Verbose: true},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s error=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	found := false
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw && it.Content == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected raw log %q not found in %+v", want, sink.items)
	}
}

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cases := []struct{ in, want string }{
		{"~", home},
		{"$HOME", home},
		{"~/app", filepath.Join(home, "app")},
		{"$HOME/app", filepath.Join(home, "app")},
		{"/srv/app", "/srv/app"},
		{"", ""},
		{"~notauser/app", "~notauser/app"},
		{"/srv/~/app", "/srv/~/app"},
	}
	for _, tc := range cases {
		got, err := expandHome(tc.in)
		if err != nil {
			t.Fatalf("expandHome(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("expandHome(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunFailsOnMissingWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	missing := filepath.Join(t.TempDir(), "nope")
	wf := workflow.Workflow{
		Name: "wd",
		Steps: []workflow.Step{
			{Name: "touch", WorkingDirectory: missing, Run: `touch marker`},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobFailed {
		t.Fatalf("status = %s want %s", res.Status, apiclient.JobFailed)
	}
}

func TestRunUsesScratchWorkdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "pwd",
		Steps: []workflow.Step{
			{Name: "where", Run: `echo "$DEPLITE_WORKDIR" && touch marker && [ -f marker ]`},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s error=%s", res.Status, res.Error)
	}
}

func TestRunMergesWorkflowAndStepEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "env",
		Env:  map[string]string{"FOO": "from-workflow", "SHARED": "wf"},
		Steps: []workflow.Step{
			{
				Name:    "show",
				Env:     map[string]string{"BAR": "from-step", "SHARED": "step"},
				Run:     `echo "FOO=$FOO BAR=$BAR SHARED=$SHARED"`,
				Verbose: true,
			},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s error=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	want := "FOO=from-workflow BAR=from-step SHARED=step"
	found := false
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw && it.Content == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in logs, got %+v", want, sink.items)
	}
}

func TestRunContinueOnErrorKeepsGoing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	shipper := joblog.New(&captureSink{}, stubSigner{})
	wf := workflow.Workflow{
		Name: "tolerant",
		Steps: []workflow.Step{
			{Name: "fail-but-ok", Run: "exit 7", ContinueOnError: true},
			{Name: "after", Run: "echo recovered"},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s error=%s", res.Status, res.Error)
	}
}

func TestRunHonorsStepShellOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	// /bin/echo isn't a shell, but exec.Command(/bin/echo, "-c", "hi")
	// will simply print its arguments. Use it as a stable witness.
	wf := workflow.Workflow{
		Name:  "shell",
		Steps: []workflow.Step{{Name: "say", Shell: "/bin/echo", Run: "hi", Verbose: true}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s error=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	found := false
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw && it.Content == "-c hi" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected '-c hi' from /bin/echo, got %+v", sink.items)
	}
}

func TestRunMasksSecretsInLogs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name:  "mask",
		Steps: []workflow.Step{{Name: "leak", Run: "echo password=hunter2", Verbose: true}},
	}
	res := Run(context.Background(), wf, "j", nil, map[string]string{"API_KEY": "hunter2"}, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s", res.Status)
	}
	_ = shipper.Flush(context.Background(), "j")
	saw := false
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw && it.Content == "password=[REDACTED]" {
			saw = true
		}
		if it.Stream == apiclient.LogStreamRaw && it.Content == "password=hunter2" {
			t.Fatalf("secret leaked in raw log")
		}
	}
	if !saw {
		t.Fatalf("expected masked line not found in %+v", sink.items)
	}
}

func TestRunMasksCredentialParamsInLogs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "mask-params",
		Params: []workflow.Param{
			{Name: "registry_token", Type: workflow.ParamString},
			{Name: "api_key", Type: workflow.ParamString, Mask: true},
			{Name: "version", Type: workflow.ParamString},
		},
		Steps: []workflow.Step{{
			Name:    "leak",
			Run:     `echo "$DEPLITE_PARAM_REGISTRY_TOKEN $DEPLITE_PARAM_API_KEY $DEPLITE_PARAM_VERSION"`,
			Verbose: true,
		}},
	}
	params := map[string]any{
		"registry_token": "dplr_secret_credential",
		"api_key":        "customer_secret_value",
		"version":        "1.2.3",
	}
	res := Run(context.Background(), wf, "j", params, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s, error=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")

	saw := false
	for _, it := range sink.items {
		if strings.Contains(it.Content, "dplr_secret_credential") {
			t.Fatalf("registry_token leaked: %q", it.Content)
		}
		if strings.Contains(it.Content, "customer_secret_value") {
			t.Fatalf("mask: true param leaked: %q", it.Content)
		}
		if it.Content == "[REDACTED] [REDACTED] 1.2.3" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("unmasked params should still be readable, got %+v", sink.items)
	}
}

func TestRunMasksCredentialParamsInValidationErrors(t *testing.T) {
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "mask-params-error",
		Params: []workflow.Param{
			{Name: "registry_token", Type: workflow.ParamString, Pattern: `^never-matches$`},
		},
		Steps: []workflow.Step{{Name: "noop", Run: "true"}},
	}
	// ResolveParams quotes the offending value, so masking has to be in place
	// before validation runs, not after.
	res := Run(context.Background(), wf, "j", map[string]any{"registry_token": "dplr_secret_credential"}, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobFailed {
		t.Fatalf("status = %s", res.Status)
	}
	_ = shipper.Flush(context.Background(), "j")
	for _, it := range sink.items {
		if strings.Contains(it.Content, "dplr_secret_credential") {
			t.Fatalf("registry_token leaked through a validation error: %q", it.Content)
		}
	}
}

func TestRunDoesNotShipRawWithoutDebug(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	// A verbose step, but debug=false: raw must stay on the host.
	wf := workflow.Workflow{
		Name:  "noraw",
		Steps: []workflow.Step{{Name: "talk", Run: "echo secret-output", Verbose: true}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	sawSystem := false
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw {
			t.Fatalf("raw shipped without debug: %q", it.Content)
		}
		if it.Stream == apiclient.LogStreamSystem {
			sawSystem = true
		}
	}
	if !sawSystem {
		t.Fatal("expected system stream events to still ship")
	}
}

func TestRunDoesNotShipRawWhenStepNotVerbose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	// debug=true, but the step did not opt into verbose: still no raw.
	wf := workflow.Workflow{
		Name:  "noraw2",
		Steps: []workflow.Step{{Name: "talk", Run: "echo secret-output"}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw {
			t.Fatalf("raw shipped for non-verbose step: %q", it.Content)
		}
	}
}

func TestStepPathAppendsHostDirs(t *testing.T) {
	got := stepPath("/opt/tools:/usr/bin")
	want := "/opt/tools:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/bin:/snap/bin"
	if got != want {
		t.Fatalf("stepPath = %q, want %q", got, want)
	}
	if got := stepPath(""); !strings.Contains(got, "/snap/bin") {
		t.Fatalf("empty PATH not backfilled: %q", got)
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin"} {
		if !strings.Contains(stepPath(""), dir) {
			t.Fatalf("empty inherited PATH is missing %s: %q", dir, stepPath(""))
		}
	}
}

func TestRunStepSeesAugmentedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	t.Setenv("PATH", "")
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name:  "path",
		Steps: []workflow.Step{{Name: "show", Run: `echo "$PATH"`, Verbose: true}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw && strings.Contains(it.Content, "/snap/bin") {
			return
		}
	}
	t.Fatalf("step PATH missing /snap/bin: %+v", sink.items)
}

func TestRunStepEnvPathOverridesWorkflowPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "path-precedence",
		Env:  map[string]string{"PATH": "workflow-path"},
		Steps: []workflow.Step{
			{Name: "workflow", Run: `echo "$PATH"`, Verbose: true},
			{Name: "step", Env: map[string]string{"PATH": "step-path"}, Run: `echo "$PATH"`, Verbose: true},
		},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), true)
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	_ = shipper.Flush(context.Background(), "j")
	seen := map[string]bool{}
	for _, it := range sink.items {
		if it.Stream == apiclient.LogStreamRaw {
			seen[it.Content] = true
		}
	}
	if !seen["workflow-path"] || !seen["step-path"] {
		t.Fatalf("workflow and step PATH values were not applied: %+v", sink.items)
	}
}

func TestRunStepCancellationKillsShellChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name: "cancel-child",
		Steps: []workflow.Step{{
			Name:             "wait",
			WorkingDirectory: dir,
			Run:              `sleep 30 & echo $! > "` + pidFile + `"; wait`,
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Result, 1)
	started := time.Now()
	go func() { done <- Run(ctx, wf, "j", nil, nil, shipper, mask.New(), false) }()

	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(pidFile)
		if err == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(body)))
			if err == nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("step did not write its child PID")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("canceled step did not finish promptly")
	}
	if elapsed := time.Since(started); elapsed >= 3*time.Second {
		t.Fatalf("canceled step took %s to finish", elapsed)
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("shell child %d remained alive after cancellation", pid)
}

func TestRunPathEnvironmentPrecedence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	t.Setenv("PATH", "")
	cases := []struct {
		name string
		wf   workflow.Workflow
		want string
	}{
		{
			name: "workflow PATH overrides default",
			wf: workflow.Workflow{
				Name:  "workflow-path",
				Env:   map[string]string{"PATH": "/workflow-path"},
				Steps: []workflow.Step{{Name: "show", Run: `echo "$PATH"`, Verbose: true}},
			},
			want: "/workflow-path",
		},
		{
			name: "step PATH overrides workflow PATH",
			wf: workflow.Workflow{
				Name:  "step-path",
				Env:   map[string]string{"PATH": "/workflow-path"},
				Steps: []workflow.Step{{Name: "show", Run: `echo "$PATH"`, Env: map[string]string{"PATH": "/step-path"}, Verbose: true}},
			},
			want: "/step-path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureSink{}
			shipper := joblog.New(sink, stubSigner{})
			res := Run(context.Background(), tc.wf, "j", nil, nil, shipper, mask.New(), true)
			if res.Status != apiclient.JobSuccess {
				t.Fatalf("status=%s err=%s", res.Status, res.Error)
			}
			if err := shipper.Flush(context.Background(), "j"); err != nil {
				t.Fatalf("flush: %v", err)
			}
			for _, item := range sink.items {
				if item.Stream == apiclient.LogStreamRaw && item.Content == tc.want {
					return
				}
			}
			t.Fatalf("PATH output %q not found in %+v", tc.want, sink.items)
		})
	}
}

func TestRunLogsStepContextOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name:  "ctx",
		Steps: []workflow.Step{{Name: "missing", Run: "definitely-not-a-real-command"}},
	}
	res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false)
	if res.Status != apiclient.JobFailed {
		t.Fatalf("status=%s", res.Status)
	}
	_ = shipper.Flush(context.Background(), "j")
	for _, it := range sink.items {
		if it.Stream != apiclient.LogStreamSystem || !strings.HasPrefix(it.Content, "step context:") {
			continue
		}
		for _, field := range []string{"shell=/bin/sh", "cwd=", "uid=", "PATH=/"} {
			if !strings.Contains(it.Content, field) {
				t.Fatalf("context line missing %q: %q", field, it.Content)
			}
		}
		return
	}
	t.Fatalf("no step context logged: %+v", sink.items)
}

func TestRunSkipsStepContextOnSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sink := &captureSink{}
	shipper := joblog.New(sink, stubSigner{})
	wf := workflow.Workflow{
		Name:  "quiet",
		Steps: []workflow.Step{{Name: "ok", Run: "true"}},
	}
	if res := Run(context.Background(), wf, "j", nil, nil, shipper, mask.New(), false); res.Status != apiclient.JobSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	_ = shipper.Flush(context.Background(), "j")
	for _, it := range sink.items {
		if strings.HasPrefix(it.Content, "step context:") {
			t.Fatalf("context logged for successful step: %q", it.Content)
		}
	}
}
