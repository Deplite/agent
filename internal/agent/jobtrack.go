package agent

import (
	"context"
	"sync"
)

// jobTracker records the lifecycle of deploy jobs so cancel events can stop
// queued or running work. A finished job is forgotten, so a late cancel for
// it is indistinguishable from a cancel for an unknown job.
type jobTracker struct {
	mu   sync.Mutex
	jobs map[string]*trackedJob
}

type trackedJob struct {
	running  bool
	canceled bool
	cancel   context.CancelFunc
}

func newJobTracker() *jobTracker {
	return &jobTracker{jobs: map[string]*trackedJob{}}
}

// queue records jobID as queued. Idempotent: it never clobbers a job that
// the run loop has already advanced to running.
func (t *jobTracker) queue(jobID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.jobs[jobID]; !ok {
		t.jobs[jobID] = &trackedJob{}
	}
}

// isCanceled reports whether jobID has been flagged by a cancel event.
func (t *jobTracker) isCanceled(jobID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	j := t.jobs[jobID]
	return j != nil && j.canceled
}

// running derives a cancelable context from parent, marks jobID running,
// and returns whether a cancel already landed while it was queued (in which
// case the returned context is already canceled).
func (t *jobTracker) running(parent context.Context, jobID string) (context.Context, context.CancelFunc, bool) {
	ctx, cancel := context.WithCancel(parent)
	t.mu.Lock()
	defer t.mu.Unlock()
	j := t.jobs[jobID]
	if j == nil {
		j = &trackedJob{}
		t.jobs[jobID] = j
	}
	j.running = true
	j.cancel = cancel
	if j.canceled {
		cancel()
	}
	return ctx, cancel, j.canceled
}

// finish forgets jobID.
func (t *jobTracker) finish(jobID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, jobID)
}

// cancel flags jobID and, if it is running, cancels its context. Returns
// whether the job was tracked and whether it was running.
func (t *jobTracker) cancel(jobID string) (found, running bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	j := t.jobs[jobID]
	if j == nil {
		return false, false
	}
	j.canceled = true
	if j.running && j.cancel != nil {
		j.cancel()
		return true, true
	}
	return true, false
}
