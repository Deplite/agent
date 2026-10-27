package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/signing"
)

// A workflow report replaces the catalog the backend holds, so these
// cases pin down when the agent is allowed to send an empty one.
func TestReportWorkflowsCatalogGuard(t *testing.T) {
	const good = "name: hello\nsteps:\n  - name: greet\n    run: \"true\"\n"
	const broken = "name: broken\nsteps:\n  - name: nope\n"

	cases := []struct {
		name      string
		files     map[string]string
		missing   bool
		wantSent  bool
		wantNames []string
	}{
		{name: "missing directory", missing: true, wantSent: false},
		{name: "every file broken", files: map[string]string{"a.yml": broken}, wantSent: false},
		{name: "empty directory", files: map[string]string{}, wantSent: true},
		{name: "one good one broken", files: map[string]string{"a.yml": good, "b.yml": broken},
			wantSent: true, wantNames: []string{"hello"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sent [][]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Workflows []struct {
						Name string `json:"name"`
					} `json:"workflows"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode report: %v", err)
				}
				names := make([]string, 0, len(body.Workflows))
				for _, wf := range body.Workflows {
					names = append(names, wf.Name)
				}
				sent = append(sent, names)
				_, _ = w.Write([]byte(`{"count":0}`))
			}))
			defer srv.Close()

			dir := filepath.Join(t.TempDir(), "workflows")
			if !c.missing {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				for name, body := range c.files {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}

			kp, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			state := newStateWriter(t.TempDir(), "test")
			reportWorkflows(context.Background(), apiclient.New(srv.URL), newSigner("agent-1", kp),
				dir, state, slog.New(slog.NewTextHandler(io.Discard, nil)))

			if got := len(sent) > 0; got != c.wantSent {
				t.Fatalf("report sent = %v, want %v", got, c.wantSent)
			}
			if !c.wantSent {
				return
			}
			if len(sent[0]) != len(c.wantNames) {
				t.Fatalf("reported %v, want %v", sent[0], c.wantNames)
			}
			for i, name := range c.wantNames {
				if sent[0][i] != name {
					t.Errorf("reported[%d] = %q, want %q", i, sent[0][i], name)
				}
			}
		})
	}
}

func TestReportWorkflowsRecordsCountsInState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":1}`))
	}))
	defer srv.Close()

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
	reportWorkflows(context.Background(), apiclient.New(srv.URL), newSigner("agent-1", kp),
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
