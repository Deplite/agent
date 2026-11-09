package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/signing"
)

// A workflow report replaces the catalog the backend holds, so these
// cases pin down when the agent is allowed to send an empty one.
func TestReportWorkflowsCatalogGuard(t *testing.T) {
	const good = "name: hello\nsteps:\n  - name: greet\n    run: \"true\"\n"
	const broken = "name: broken\nsteps:\n  - name: nope\n"
	type report struct {
		workflows []string
		invalid   []apiclient.InvalidWorkflow
	}

	cases := []struct {
		name        string
		files       map[string]string
		missing     bool
		wantSent    bool
		wantNames   []string
		wantInvalid []apiclient.InvalidWorkflow
	}{
		{name: "missing directory", missing: true, wantSent: false},
		{name: "every file broken", files: map[string]string{"a.yml": broken}, wantSent: false},
		{name: "empty directory", files: map[string]string{}, wantSent: true},
		{name: "one good one broken", files: map[string]string{"a.yml": good, "b.yml": broken},
			wantSent: true, wantNames: []string{"hello"}},
		{name: "duplicate only", files: map[string]string{"a.yml": good, "team/hello.yml": good}, wantSent: true,
			wantInvalid: []apiclient.InvalidWorkflow{{Name: "hello", Code: "duplicate_name", Reason: `workflow "hello": name is defined in 2 files (a.yml, team/hello.yml)`, Files: []string{"a.yml", "team/hello.yml"}}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sent []report
			client := reportTestClient(func(r *http.Request) {
				var body struct {
					Workflows []struct {
						Name string `json:"name"`
					} `json:"workflows"`
					Invalid []apiclient.InvalidWorkflow `json:"invalid"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode report: %v", err)
				}
				names := make([]string, 0, len(body.Workflows))
				for _, wf := range body.Workflows {
					names = append(names, wf.Name)
				}
				sent = append(sent, report{workflows: names, invalid: body.Invalid})
			})

			dir := filepath.Join(t.TempDir(), "workflows")
			if !c.missing {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				for name, body := range c.files {
					path := filepath.Join(dir, name)
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}

			kp, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			state := newStateWriter(t.TempDir(), "test")
			reportWorkflows(context.Background(), client, newSigner("agent-1", kp),
				dir, state, slog.New(slog.NewTextHandler(io.Discard, nil)))

			if got := len(sent) > 0; got != c.wantSent {
				t.Fatalf("report sent = %v, want %v", got, c.wantSent)
			}
			if !c.wantSent {
				return
			}
			if sent[0].invalid == nil {
				t.Fatal("invalid must be an array")
			}
			if len(sent[0].workflows) != len(c.wantNames) {
				t.Fatalf("reported %v, want %v", sent[0].workflows, c.wantNames)
			}
			for i, name := range c.wantNames {
				if sent[0].workflows[i] != name {
					t.Errorf("reported[%d] = %q, want %q", i, sent[0].workflows[i], name)
				}
			}
			if len(sent[0].invalid) != len(c.wantInvalid) {
				t.Fatalf("invalid workflows = %+v, want %+v", sent[0].invalid, c.wantInvalid)
			}
			for i, want := range c.wantInvalid {
				got := sent[0].invalid[i]
				if got.Name != want.Name || got.Code != want.Code || got.Reason != want.Reason || strings.Join(got.Files, ",") != strings.Join(want.Files, ",") {
					t.Errorf("invalid[%d] = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

func TestReportWorkflowsKeepsCatalogForBrokenDirectorySymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "workflows")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	sent := false
	client := reportTestClient(func(*http.Request) { sent = true })
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	reportWorkflows(context.Background(), client, newSigner("agent-1", kp), link,
		newStateWriter(t.TempDir(), "test"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if sent {
		t.Fatal("reported a broken workflow directory symlink")
	}
}

func TestReportWorkflowsWarnsWhenBackendDoesNotRecordInvalidName(t *testing.T) {
	dir := t.TempDir()
	workflowBody := func(name string) []byte {
		return []byte("name: " + name + "\nsteps:\n  - name: run\n    run: echo hi\n")
	}
	for _, name := range []string{"alpha", "beta"} {
		for _, file := range []string{name + ".yml", filepath.Join("team", name+".yml")} {
			path := filepath.Join(dir, file)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, workflowBody(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client := reportTestClientWithResponse(nil, `{"count":0,"invalid":["alpha"]}`)
	reportWorkflows(context.Background(), client, newSigner("agent-1", kp), dir,
		newStateWriter(t.TempDir(), "test"), logger)
	var missingWarnings []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `msg="backend did not record invalid workflow"`) {
			missingWarnings = append(missingWarnings, line)
		}
	}
	if len(missingWarnings) != 1 || !strings.Contains(missingWarnings[0], "workflow=beta") {
		t.Fatalf("missing-name warnings = %v", missingWarnings)
	}

	logs.Reset()
	client = reportTestClientWithResponse(nil, `{"count":0}`)
	reportWorkflows(context.Background(), client, newSigner("agent-1", kp), dir,
		newStateWriter(t.TempDir(), "test"), logger)
	if strings.Contains(logs.String(), `msg="backend did not record invalid workflow"`) {
		t.Fatalf("legacy response emitted missing-name warning: %s", logs.String())
	}
}

func TestRunOneJobReportsDuplicateWorkflowAsInvalid(t *testing.T) {
	dir := t.TempDir()
	workflowBody := []byte("name: hello\nsteps:\n  - name: run\n    run: echo hi\n")
	if err := os.WriteFile(filepath.Join(dir, "hello.yml"), workflowBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "team"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "team", "hello.yml"), workflowBody, 0o600); err != nil {
		t.Fatal(err)
	}

	var got apiclient.JobResult
	client := reportTestClient(func(r *http.Request) {
		if r.URL.Path != "/agent/jobs/job-1/result" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode job result: %v", err)
		}
	})

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runOneJob(context.Background(), client, newSigner("agent-1", kp), apiclient.DeployPayload{
		JobID: "job-1", WorkflowName: "hello",
	}, dir, nil, nil, newJobTracker(), nil, nil, "agent-1", logger)

	want := `workflow "hello" is invalid: name is defined in 2 files (hello.yml, team/hello.yml)`
	if got.Status != apiclient.JobFailed || got.ErrorMessage != want {
		t.Fatalf("job result = %+v, want failed %q", got, want)
	}
}

func TestReportWorkflowsRecordsCountsInState(t *testing.T) {
	client := reportTestClient(nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yml"),
		[]byte("name: hello\nsteps:\n  - name: greet\n    run: \"true\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"),
		[]byte("name: broken\nsteps:\n  - name: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	state := newStateWriter(dataDir, "test")
	reportWorkflows(context.Background(), client, newSigner("agent-1", kp),
		dir, state, slog.New(slog.NewTextHandler(io.Discard, nil)))

	got, err := ReadRunState(dataDir)
	if err != nil {
		t.Fatalf("ReadRunState: %v", err)
	}
	if got.WorkflowsReported != 1 || got.WorkflowsInvalid != 1 {
		t.Errorf("state = %d valid / %d invalid, want 1 / 1", got.WorkflowsReported, got.WorkflowsInvalid)
	}
	if got.PID != os.Getpid() {
		t.Errorf("state pid = %d, want %d", got.PID, os.Getpid())
	}
}

type reportRoundTripper struct {
	capture  func(*http.Request)
	response string
}

func (f reportRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.capture != nil {
		f.capture(r)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(f.response)),
		Request:    r,
	}, nil
}

func reportTestClient(capture func(*http.Request)) *apiclient.Client {
	return reportTestClientWithResponse(capture, `{"count":0,"ok":true}`)
}

func reportTestClientWithResponse(capture func(*http.Request), response string) *apiclient.Client {
	client := apiclient.New("http://backend.test")
	client.HTTPClient = &http.Client{Transport: reportRoundTripper{capture: capture, response: response}}
	return client
}
