package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const runStateFile = "state.json"

// RunState is what a running agent publishes about itself so `status`
// and `doctor` can report on it without talking to the backend.
type RunState struct {
	PID                int       `json:"pid"`
	Version            string    `json:"version"`
	StartedAt          time.Time `json:"startedAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
	StreamConnected    bool      `json:"streamConnected"`
	StreamConnectedAt  time.Time `json:"streamConnectedAt,omitempty"`
	LastHeartbeatAt    time.Time `json:"lastHeartbeatAt,omitempty"`
	LastHeartbeatError string    `json:"lastHeartbeatError,omitempty"`
	WorkflowsReported  int       `json:"workflowsReported"`
	WorkflowsInvalid   int       `json:"workflowsInvalid"`
	CurrentJobID       string    `json:"currentJobId,omitempty"`
	CurrentWorkflow    string    `json:"currentWorkflow,omitempty"`
}

// Alive reports whether the process that wrote this state still exists.
// Only meaningful when read from the machine that wrote it.
func (s RunState) Alive() bool {
	if s.PID <= 0 {
		return false
	}
	p, err := os.FindProcess(s.PID)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// ReadRunState loads the state published by a running agent. Returns
// os.ErrNotExist when no agent has ever started against this data dir.
func ReadRunState(dataDir string) (RunState, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, runStateFile))
	if err != nil {
		return RunState{}, err
	}
	var s RunState
	if err := json.Unmarshal(b, &s); err != nil {
		return RunState{}, err
	}
	return s, nil
}

type stateWriter struct {
	path string
	mu   sync.Mutex
	cur  RunState
}

func newStateWriter(dataDir, version string) *stateWriter {
	w := &stateWriter{
		path: filepath.Join(dataDir, runStateFile),
		cur: RunState{
			PID:       os.Getpid(),
			Version:   version,
			StartedAt: time.Now().UTC(),
		},
	}
	w.update(func(*RunState) {})
	return w
}

// update mutates the published state and rewrites the file. Write
// failures are ignored: the state file is a convenience for the CLI, not
// something a job depends on.
func (w *stateWriter) update(fn func(*RunState)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(&w.cur)
	w.cur.UpdatedAt = time.Now().UTC()
	b, err := json.Marshal(w.cur)
	if err != nil {
		return
	}
	_ = writeFileAtomic(w.path, b)
}

func (w *stateWriter) remove() { _ = os.Remove(w.path) }
