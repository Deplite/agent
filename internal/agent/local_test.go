package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/workflow"
)

const helloWorkflow = `
name: hello
params:
  - name: greeting
    type: string
    default: Hello
  - name: times
    type: number
    default: 2
  - name: loud
    type: boolean
    default: false
steps:
  - id: greet
    name: greet
    run: |
      echo "$DEPLITE_PARAM_GREETING/$DEPLITE_PARAM_TIMES/$DEPLITE_PARAM_LOUD"
      echo "line=ok" >> "$DEPLITE_OUTPUT"
outputs:
  - name: line
    type: string
    from: greet.line
`

func writeWorkflows(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Flag values always arrive as text, so a number or boolean param has to
// be converted before ResolveParams sees it or every typed param would
// be rejected from the command line.
func TestCoerceParams(t *testing.T) {
	wf := workflow.Workflow{Params: []workflow.Param{
		{Name: "greeting", Type: workflow.ParamString},
		{Name: "times", Type: workflow.ParamNumber},
		{Name: "loud", Type: workflow.ParamBoolean},
	}}
	got := CoerceParams(wf, map[string]string{
		"greeting": "hi",
		"times":    "3",
		"loud":     "true",
		"unknown":  "x",
	})
	if got["greeting"] != "hi" {
		t.Errorf("greeting = %#v, want the string unchanged", got["greeting"])
	}
	if got["times"] != float64(3) {
		t.Errorf("times = %#v, want float64(3)", got["times"])
	}
	if got["loud"] != true {
		t.Errorf("loud = %#v, want true", got["loud"])
	}
	if got["unknown"] != "x" {
		t.Errorf("unknown = %#v, want it passed through for ResolveParams to reject", got["unknown"])
	}
	if _, err := wf.ResolveParams(got); err == nil {
		t.Error("ResolveParams accepted an undeclared param")
	}
}

func TestLoadWorkflowNamesAlternatives(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"hello.yml": helloWorkflow})

	if _, err := LoadWorkflow(dir, "hello"); err != nil {
		t.Fatalf("LoadWorkflow: %v", err)
	}
	_, err := LoadWorkflow(dir, "helo")
	if err == nil {
		t.Fatal("LoadWorkflow accepted a name that does not exist")
	}
	if !strings.Contains(err.Error(), "hello") {
		t.Errorf("error %q does not list the available names", err)
	}
}

func TestLocalSecretsPrefersExplicitOverride(t *testing.T) {
	t.Setenv("DEPLITE_SECRET_FROM_ENV", "env-value")
	t.Setenv("DEPLITE_SECRET_OVERRIDDEN", "env-value")
	wf := workflow.Workflow{Secrets: []workflow.Secret{
		{Name: "FROM_ENV"}, {Name: "OVERRIDDEN"}, {Name: "UNBOUND"},
	}}

	got := LocalSecrets(wf, map[string]string{"OVERRIDDEN": "flag-value"})
	if got["FROM_ENV"] != "env-value" {
		t.Errorf("FROM_ENV = %q, want the environment value", got["FROM_ENV"])
	}
	if got["OVERRIDDEN"] != "flag-value" {
		t.Errorf("OVERRIDDEN = %q, want the flag to win", got["OVERRIDDEN"])
	}
	if _, ok := got["UNBOUND"]; ok {
		t.Error("UNBOUND was bound without a value")
	}
}

func TestDryRunRejectsMissingRequiredSecret(t *testing.T) {
	wf := workflow.Workflow{
		Name:    "needs-secret",
		Secrets: []workflow.Secret{{Name: "TOKEN", Required: true}},
		Steps:   []workflow.Step{{Name: "noop", Run: "true"}},
	}
	var out strings.Builder
	err := DryRun(wf, nil, nil, &out)
	if err == nil {
		t.Fatal("DryRun accepted a plan a real run would reject")
	}
	if !strings.Contains(err.Error(), "TOKEN") {
		t.Errorf("error %q does not name the missing secret", err)
	}
}

func TestDryRunMasksParamValues(t *testing.T) {
	wf := workflow.Workflow{
		Name:   "masked",
		Params: []workflow.Param{{Name: "api_key", Type: workflow.ParamString, Mask: true}},
		Steps:  []workflow.Step{{Name: "noop", Run: "true"}},
	}
	var out strings.Builder
	if err := DryRun(wf, map[string]any{"api_key": "s3cr3t"}, nil, &out); err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Error("dry run printed a masked param value")
	}
	if !strings.Contains(out.String(), "DEPLITE_PARAM_API_KEY") {
		t.Error("dry run did not list the injected env key")
	}
}

func TestDryRunOnlyAdvisesExternalApproval(t *testing.T) {
	wf := workflow.Workflow{
		Name:  "protected",
		Steps: []workflow.Step{{Name: "noop", Run: "true"}},
		On: &workflow.On{Webhook: &workflow.OnWebhook{Approval: &workflow.WebhookApproval{
			Methods: []string{"hmac", "totp"},
		}}},
	}
	var out strings.Builder
	if err := DryRun(wf, nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "외부 실행 승인: hmac, totp") || strings.Contains(out.String(), "로컬 실행에는 적용되지 않습니다") == false {
		t.Fatalf("dry run approval guidance missing: %s", out.String())
	}
}

func TestRunLocalExecutesAndCapturesOutputs(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"hello.yml": helloWorkflow})
	wf, err := LoadWorkflow(dir, "hello")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()

	var out strings.Builder
	params := CoerceParams(wf, map[string]string{"greeting": "hi", "times": "3"})
	res := RunLocal(context.Background(), wf, params, nil, LocalRunOptions{
		DataDir: dataDir,
		Out:     &out,
	})
	if res.Status != apiclient.JobSuccess {
		t.Fatalf("status = %s (%s), want success", res.Status, res.Error)
	}
	if got := out.String(); !strings.Contains(got, "hi/3/false") {
		t.Errorf("step output missing from %q", got)
	}
	if res.Outputs["line"] != "ok" {
		t.Errorf("outputs = %#v, want line=ok", res.Outputs)
	}
	// The mirror is what `deplite-agent logs` replays afterwards.
	entries, err := os.ReadDir(ResolveLogDir(dataDir))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no mirrored job log under %s (%v)", ResolveLogDir(dataDir), err)
	}
}

func TestRunLocalReportsFailingStep(t *testing.T) {
	dir := writeWorkflows(t, map[string]string{"boom.yml": "name: boom\nsteps:\n  - name: boom\n    run: exit 7\n"})
	wf, err := LoadWorkflow(dir, "boom")
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	res := RunLocal(context.Background(), wf, nil, nil, LocalRunOptions{Out: &out})
	if res.Status != apiclient.JobFailed {
		t.Errorf("status = %s, want failed", res.Status)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", res.ExitCode)
	}
}

func TestParseKeyValues(t *testing.T) {
	got, err := ParseKeyValues([]string{"a=1", "b=with=equals", "c="}, "--param")
	if err != nil {
		t.Fatalf("ParseKeyValues: %v", err)
	}
	want := map[string]string{"a": "1", "b": "with=equals", "c": ""}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := ParseKeyValues([]string{"novalue"}, "--param"); err == nil {
		t.Error("accepted a pair without =")
	}
}
