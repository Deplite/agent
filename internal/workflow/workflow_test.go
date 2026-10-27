package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestScanReadsValidWorkflows(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "b.yml", `
name: build
secrets: [GH_TOKEN]
timeout-minutes: 30
steps:
  - name: compile
    working-directory: /tmp
    timeout-minutes: 10
    run: go build ./...
  - name: test
    verbose: true
    run: go test ./...
`)
	writeFile(t, dir, "a.yaml", `
name: deploy
steps:
  - name: ship
    run: echo ok
`)

	wfs, bad := Scan(dir)
	if len(bad) != 0 {
		t.Fatalf("unexpected errors: %v", bad)
	}
	if len(wfs) != 2 {
		t.Fatalf("got %d workflows, want 2", len(wfs))
	}
	if wfs[0].Name != "build" || wfs[1].Name != "deploy" {
		t.Fatalf("workflows not sorted by name: %+v", wfs)
	}
	if got := wfs[0].VerboseSteps(); len(got) != 1 || got[0] != "test" {
		t.Fatalf("verbose steps = %v", got)
	}
	if wfs[0].TimeoutMinutes != 30 {
		t.Fatalf("workflow TimeoutMinutes = %d, want 30", wfs[0].TimeoutMinutes)
	}
	if wfs[0].Steps[0].TimeoutMinutes != 10 || wfs[0].Steps[0].WorkingDirectory != "/tmp" {
		t.Fatalf("step kebab-case fields not parsed: %+v", wfs[0].Steps[0])
	}
	if names := wfs[0].SecretNames(); len(names) != 1 || names[0] != "GH_TOKEN" {
		t.Fatalf("secrets legacy string form not parsed: %+v", wfs[0].Secrets)
	}
	if !wfs[0].Secrets[0].Required {
		t.Fatal("legacy secret should default to required=true")
	}
}

func TestScanReadsFullSchema(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.yml", `
name: deploy-staging
description: "Stage deploy"
version: "1.0.0"
schema-version: 1

params:
  - name: target-tag
    type: string
    required: true
    pattern: "^v[0-9]+$"
  - name: replicas
    type: number
    default: 2
    min: 1
    max: 10
  - name: region
    type: enum
    required: true
    options: [a, b]

secrets:
  - name: REGISTRY_TOKEN
    required: true
    description: "push token"
    scope: [push]

outputs:
  - name: deployed-sha
    type: string
    from: build.sha

retry:
  max-attempts: 3
  backoff: exponential
  initial-delay-seconds: 5
  max-delay-seconds: 60

steps:
  - id: build
    name: build
    run: echo sha=abc >> $DEPLITE_OUTPUT
  - id: push
    name: push
    run: echo ok
    retry:
      max-attempts: 5
      backoff: linear
`)
	wfs, bad := Scan(dir)
	if len(bad) != 0 {
		t.Fatalf("unexpected errors: %v", bad)
	}
	if len(wfs) != 1 {
		t.Fatalf("got %d workflows, want 1", len(wfs))
	}
	w := wfs[0]
	if w.Description == "" || w.Version == "" || w.SchemaVersion != 1 {
		t.Fatalf("meta fields not parsed: %+v", w)
	}
	if len(w.Params) != 3 {
		t.Fatalf("params: %+v", w.Params)
	}
	if w.Params[0].Pattern != "^v[0-9]+$" {
		t.Fatalf("pattern not parsed: %+v", w.Params[0])
	}
	if w.Secrets[0].Name != "REGISTRY_TOKEN" || !w.Secrets[0].Required || len(w.Secrets[0].Scope) != 1 {
		t.Fatalf("secret not parsed: %+v", w.Secrets[0])
	}
	if w.Retry == nil || w.Retry.MaxAttempts != 3 {
		t.Fatalf("workflow retry: %+v", w.Retry)
	}
	if w.Steps[1].Retry == nil || w.Steps[1].Retry.MaxAttempts != 5 {
		t.Fatalf("step retry: %+v", w.Steps[1].Retry)
	}
}

func TestApprovalPolicyLoadStrictAndRedacted(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "hmac.yaml")
	writeFile(t, dir, "hmac.yaml", "signer: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n")
	path := filepath.Join(dir, "protected.yml")
	body := fmt.Sprintf(`name: protected
on:
  webhook:
    refs: [main]
    approval:
      hmac:
        keys-file: %s
steps:
  - name: run
    run: echo ok
`, keys)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	wf, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if wf.ApprovalPolicy() == nil || strings.Join(wf.ApprovalMethods(), ",") != "hmac" {
		t.Fatalf("policy/methods = %v / %v", wf.ApprovalPolicy(), wf.ApprovalMethods())
	}
	encoded, err := json.Marshal(wf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"approval":{"methods":["hmac"]}`) || strings.Contains(string(encoded), keys) {
		t.Fatalf("workflow JSON should expose methods only: %s", encoded)
	}

	badKey := strings.Replace(body, "keys-file:", "unknown-file:", 1)
	if err := os.WriteFile(path, []byte(badKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unknown nested key error = %v", err)
	}
	noMethods := strings.Replace(body, "      hmac:\n        keys-file: "+keys+"\n", "", 1)
	noMethods = strings.Replace(noMethods, "    approval:\n", "    approval: {}\n", 1)
	if err := os.WriteFile(path, []byte(noMethods), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("empty approval config loaded")
	}

	if err := os.WriteFile(path, []byte(strings.Replace(body, keys, "relative.yaml", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("relative approval path loaded")
	}
}

func TestScanReloadsApprovalFiles(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	keyPath := filepath.Join(keysDir, "hmac.yaml")
	if err := os.WriteFile(keyPath, []byte("signer: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "protected.yml", fmt.Sprintf(`name: protected
on:
  webhook:
    approval:
      hmac:
        keys-file: %s
steps:
  - name: run
    run: echo ok
`, keyPath))
	if wfs, bad := Scan(dir); len(wfs) != 1 || len(bad) != 0 {
		t.Fatalf("initial scan: workflows=%d errors=%v", len(wfs), bad)
	}
	if err := os.WriteFile(keyPath, []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if wfs, bad := Scan(dir); len(wfs) != 0 || len(bad) != 1 {
		t.Fatalf("scan did not reload approval file: workflows=%d errors=%v", len(wfs), bad)
	}
}

func TestScanCollectsParseErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yml", "this is: : invalid: : yaml: :")
	writeFile(t, dir, "ok.yml", "name: w\nsteps:\n  - name: s\n    run: echo hi\n")

	wfs, bad := Scan(dir)
	if len(wfs) != 1 {
		t.Fatalf("got %d good, want 1", len(wfs))
	}
	if len(bad) != 1 {
		t.Fatalf("got %d bad, want 1: %+v", len(bad), bad)
	}
}

func TestValidateRejectsBadShapes(t *testing.T) {
	mkStep := func() Step { return Step{Name: "a", Run: "x"} }
	cases := []struct {
		name string
		wf   Workflow
	}{
		{"empty name", Workflow{Steps: []Step{mkStep()}}},
		{"no steps", Workflow{Name: "x"}},
		{"step missing run", Workflow{Name: "x", Steps: []Step{{Name: "a"}}}},
		{"duplicate step name", Workflow{Name: "x", Steps: []Step{mkStep(), mkStep()}}},
		{"duplicate step id", Workflow{Name: "x", Steps: []Step{
			{ID: "s", Name: "a", Run: "x"}, {ID: "s", Name: "b", Run: "y"},
		}}},
		{"unsupported schema-version", Workflow{Name: "x", SchemaVersion: 99, Steps: []Step{mkStep()}}},
		{"required + default", Workflow{Name: "x", Steps: []Step{mkStep()}, Params: []Param{
			{Name: "p", Type: ParamString, Required: true, Default: "x"},
		}}},
		{"enum without options", Workflow{Name: "x", Steps: []Step{mkStep()}, Params: []Param{
			{Name: "p", Type: ParamEnum},
		}}},
		{"options on non-enum", Workflow{Name: "x", Steps: []Step{mkStep()}, Params: []Param{
			{Name: "p", Type: ParamString, Options: []string{"a"}},
		}}},
		{"pattern on non-string", Workflow{Name: "x", Steps: []Step{mkStep()}, Params: []Param{
			{Name: "p", Type: ParamNumber, Pattern: "x"},
		}}},
		{"invalid pattern", Workflow{Name: "x", Steps: []Step{mkStep()}, Params: []Param{
			{Name: "p", Type: ParamString, Pattern: "[bad"},
		}}},
		{"bad secret name", Workflow{Name: "x", Steps: []Step{mkStep()}, Secrets: []Secret{{Name: "lower"}}}},
		{"output unknown id", Workflow{Name: "x", Steps: []Step{mkStep()}, Outputs: []Output{
			{Name: "o", Type: OutputString, From: "nope.k"},
		}}},
		{"output bad from", Workflow{Name: "x", Steps: []Step{mkStep()}, Outputs: []Output{
			{Name: "o", Type: OutputString, From: "nodot"},
		}}},
		{"retry zero attempts", Workflow{Name: "x", Steps: []Step{mkStep()}, Retry: &Retry{MaxAttempts: 0}}},
		{"retry bad backoff", Workflow{Name: "x", Steps: []Step{mkStep()}, Retry: &Retry{MaxAttempts: 2, Backoff: "warp"}}},
		{"retry initial > max", Workflow{Name: "x", Steps: []Step{mkStep()}, Retry: &Retry{
			MaxAttempts: 2, InitialDelaySeconds: 10, MaxDelaySeconds: 5,
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.wf.Validate(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestResolveParamsFillsDefaultsAndChecks(t *testing.T) {
	d := 5.0
	w := Workflow{
		Name: "x",
		Params: []Param{
			{Name: "tag", Type: ParamString, Required: true, Pattern: "^v[0-9]+$"},
			{Name: "count", Type: ParamNumber, Default: 3.0, Min: &d},
			{Name: "env", Type: ParamEnum, Required: true, Options: []string{"dev", "prod"}},
		},
		Steps: []Step{{Name: "a", Run: "x"}},
	}

	ok, err := w.ResolveParams(map[string]any{"tag": "v1", "env": "prod"})
	if err != nil {
		t.Fatalf("resolve ok: %v", err)
	}
	if ok["tag"] != "v1" || ok["env"] != "prod" || ok["count"].(float64) != 3.0 {
		t.Fatalf("resolved: %+v", ok)
	}

	if _, err := w.ResolveParams(map[string]any{"env": "prod"}); err == nil {
		t.Fatal("missing required should fail")
	}
	if _, err := w.ResolveParams(map[string]any{"tag": "bad", "env": "prod"}); err == nil {
		t.Fatal("pattern mismatch should fail")
	}
	if _, err := w.ResolveParams(map[string]any{"tag": "v1", "env": "test"}); err == nil {
		t.Fatal("enum mismatch should fail")
	}
	if _, err := w.ResolveParams(map[string]any{"tag": "v1", "env": "prod", "unknown": 1}); err == nil {
		t.Fatal("undeclared param should fail")
	}
	if _, err := w.ResolveParams(map[string]any{"tag": "v1", "env": "prod", "count": 1.0}); err == nil {
		t.Fatal("below min should fail")
	}
}

func TestResolveOutputs(t *testing.T) {
	w := Workflow{
		Outputs: []Output{
			{Name: "sha", Type: OutputString, From: "build.commit"},
			{Name: "missing", Type: OutputString, From: "build.nope"},
		},
	}
	got := w.ResolveOutputs(StepOutputs{"build": {"commit": "abc"}})
	if got["sha"] != "abc" || got["missing"] != "" {
		t.Fatalf("resolved: %+v", got)
	}
}

func TestMaskedParams(t *testing.T) {
	w := Workflow{
		Params: []Param{
			{Name: "api_key", Type: ParamString, Mask: true},
			{Name: "version", Type: ParamString},
		},
	}
	got := w.MaskedParams()
	if !got["api_key"] {
		t.Fatal("mask: true should be honored")
	}
	// The workflow does not declare registry_token at all here: the backend
	// owns that value, so masking it cannot depend on the author asking.
	if !got["registry_token"] {
		t.Fatal("server credential params should be masked unconditionally")
	}
	if got["version"] {
		t.Fatal("ordinary params should stay readable")
	}
}

func TestMaskIsNotReportedToBackend(t *testing.T) {
	body, err := json.Marshal(Param{Name: "api_key", Type: ParamString, Mask: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "mask") {
		t.Fatalf("mask is local policy and must not be reported: %s", body)
	}
}

func TestScanMissingDirIsNotFatal(t *testing.T) {
	wfs, bad := Scan(filepath.Join(t.TempDir(), "missing"))
	if len(wfs) != 0 || len(bad) != 0 {
		t.Fatalf("missing dir should be silent, got wfs=%v bad=%v", wfs, bad)
	}
}

func parseOne(t *testing.T, body string) (Workflow, error) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "w.yml", body)
	wfs, bad := Scan(dir)
	if len(bad) > 0 {
		return Workflow{}, bad[0].Err
	}
	if len(wfs) != 1 {
		t.Fatalf("got %d workflows, want 1", len(wfs))
	}
	return wfs[0], nil
}

const onSteps = "steps:\n  - name: ship\n    run: echo ok\n"

func TestOnBlockParsed(t *testing.T) {
	wf, err := parseOne(t, `
name: deploy
on:
  webhook:
    refs: [main, "release/*"]
`+onSteps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !wf.Callable() {
		t.Fatal("workflow should be callable")
	}
	if got := wf.On.Webhook.Refs; len(got) != 2 || got[0] != "main" {
		t.Fatalf("refs = %v", got)
	}
}

func TestWorkflowWithoutOnIsNotCallable(t *testing.T) {
	wf, err := parseOne(t, "name: deploy\n"+onSteps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if wf.Callable() {
		t.Fatal("a workflow without on: must not be callable")
	}
	if wf.AllowsRef("main") {
		t.Fatal("a workflow without on: must not allow any ref")
	}
}

func TestOnRejectsMalformedBlocks(t *testing.T) {
	cases := map[string]string{
		"typo in refs": "on:\n  webhook:\n    ref: [main]\n",
		"empty ref":    "on:\n  webhook:\n    refs: [\"\"]\n",
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOne(t, "name: deploy\n"+block+onSteps); err == nil {
				t.Fatal("expected the workflow to be rejected")
			}
		})
	}
}

// An `on:` block that names no trigger declares nothing, which is the
// same as having no block: closed, and visible in the console as such.
func TestOnWithoutTriggerIsNotCallable(t *testing.T) {
	for name, block := range map[string]string{"empty on": "on:\n", "no trigger": "on: {}\n"} {
		t.Run(name, func(t *testing.T) {
			wf, err := parseOne(t, "name: deploy\n"+block+onSteps)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if wf.Callable() {
				t.Fatal("workflow should not be callable")
			}
		})
	}
}

// `webhook:` with nothing under it is the shortest way to say "any ref".
func TestBareWebhookAllowsAnyRef(t *testing.T) {
	wf, err := parseOne(t, "name: deploy\non:\n  webhook:\n"+onSteps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !wf.Callable() || !wf.AllowsRef("anything") {
		t.Fatalf("bare webhook should allow any ref: callable=%v", wf.Callable())
	}
}

// The backend applies the same bounds to the report, where one bad entry
// would cost the whole catalog instead of this one workflow.
func TestOnRefBounds(t *testing.T) {
	long := strings.Repeat("a", 256)
	if _, err := parseOne(t, "name: deploy\non:\n  webhook:\n    refs: [\""+long+"\"]\n"+onSteps); err == nil {
		t.Fatal("a ref pattern over 255 characters should be rejected")
	}
	var many strings.Builder
	for i := 0; i < 51; i++ {
		fmt.Fprintf(&many, "      - r%d\n", i)
	}
	if _, err := parseOne(t, "name: deploy\non:\n  webhook:\n    refs:\n"+many.String()+onSteps); err == nil {
		t.Fatal("more than 50 ref patterns should be rejected")
	}
}

// A yaml written for a later agent still loads: an unknown trigger just
// declares nothing this agent can act on.
func TestUnknownTriggerIsIgnored(t *testing.T) {
	wf, err := parseOne(t, "name: deploy\non:\n  schedule:\n    cron: '0 0 * * *'\n"+onSteps)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if wf.Callable() {
		t.Fatal("an unknown trigger must not make the workflow callable")
	}
}

func TestAllowsRef(t *testing.T) {
	cases := []struct {
		refs []string
		ref  string
		want bool
	}{
		{nil, "anything", true},
		{[]string{}, "anything", true},
		{[]string{"main"}, "main", true},
		{[]string{"main"}, "Main", false},
		{[]string{"main"}, "mainline", false},
		{[]string{"main"}, "", false},
		{[]string{"main"}, "refs/heads/main", false},
		{[]string{"main", "develop"}, "develop", true},
		{[]string{"release/*"}, "release/1.2", true},
		// `*` crosses the separator, matching the backend's matcher.
		{[]string{"release/*"}, "release/1.2/rc", true},
		{[]string{"release/**"}, "release/1.2/rc", true},
		{[]string{"release/*"}, "release/", true},
		{[]string{"release/*"}, "hotfix/1.2", false},
		{[]string{"*"}, "refs/heads/main", true},
		// Everything but `*` is literal, and a pattern without `*` is
		// compared exactly.
		{[]string{"v?.0"}, "v1.0", false},
		{[]string{"v?.0"}, "v?.0", true},
		{[]string{"v[0-9].0"}, "v1.0", false},
		{[]string{"v[0-9].0"}, "v[0-9].0", true},
		{[]string{"v1.0"}, "v1x0", false},
	}
	for _, c := range cases {
		wf := Workflow{On: &On{Webhook: &OnWebhook{Refs: c.refs}}}
		if got := wf.AllowsRef(c.ref); got != c.want {
			t.Errorf("AllowsRef(%q) with refs %v = %v, want %v", c.ref, c.refs, got, c.want)
		}
	}
}
