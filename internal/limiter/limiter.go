// Package limiter enforces per-workflow rate limits (cooldown, token
// bucket) with state persisted under one JSON file per workflow.
package limiter

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Deplite/agent/internal/workflow"
)

type Decision struct {
	Allowed    bool
	LimitType  string
	RetryAfter time.Duration
}

type state struct {
	CooldownLastFinishAt     time.Time `json:"cooldownLastFinishAt,omitempty"`
	CooldownLastFinishStatus string    `json:"cooldownLastFinishStatus,omitempty"`
	BucketTokens             float64   `json:"bucketTokens"`
	BucketUpdatedAt          time.Time `json:"bucketUpdatedAt,omitempty"`
	BucketInit               bool      `json:"bucketInit,omitempty"`
}

type Manager struct {
	mu  sync.Mutex
	dir string
}

func New(dir string) *Manager { return &Manager{dir: dir} }

// TryAcquire evaluates every limit. If all pass, mutates state for
// start-time bookkeeping (bucket token deduction) and persists.
func (m *Manager) TryAcquire(wf *workflow.Workflow, now time.Time) (Decision, error) {
	if len(wf.Limits) == 0 {
		return Decision{Allowed: true}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.load(wf.Name)
	if err != nil {
		return Decision{}, err
	}

	worst := Decision{Allowed: true}
	for _, l := range wf.Limits {
		d := checkLimit(l, st, now)
		if !d.Allowed && d.RetryAfter > worst.RetryAfter {
			worst = d
		}
	}
	if !worst.Allowed {
		return worst, nil
	}

	for _, l := range wf.Limits {
		applyStart(l, st, now)
	}
	if err := m.save(wf.Name, st); err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: true}, nil
}

// Release records finish-time bookkeeping (cooldown timestamp).
func (m *Manager) Release(wf *workflow.Workflow, now time.Time, status string) error {
	if len(wf.Limits) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.load(wf.Name)
	if err != nil {
		return err
	}
	for _, l := range wf.Limits {
		if l.Type == workflow.LimitCooldown {
			st.CooldownLastFinishAt = now
			st.CooldownLastFinishStatus = status
		}
	}
	return m.save(wf.Name, st)
}

// BypassTypes lists the limit types that would have been evaluated, so
// callers can record what was skipped under force=true.
func BypassTypes(wf *workflow.Workflow) []string {
	out := make([]string, 0, len(wf.Limits))
	for _, l := range wf.Limits {
		out = append(out, string(l.Type))
	}
	return out
}

func checkLimit(l workflow.Limit, st *state, now time.Time) Decision {
	switch l.Type {
	case workflow.LimitCooldown:
		if st.CooldownLastFinishAt.IsZero() {
			return Decision{Allowed: true}
		}
		if l.SuccessOnly() && st.CooldownLastFinishStatus != "success" {
			return Decision{Allowed: true}
		}
		next := st.CooldownLastFinishAt.Add(l.Cooldown())
		if !now.Before(next) {
			return Decision{Allowed: true}
		}
		return Decision{Allowed: false, LimitType: string(l.Type), RetryAfter: next.Sub(now)}
	case workflow.LimitBucket:
		tokens := currentTokens(l, st, now)
		if tokens >= 1.0 {
			return Decision{Allowed: true}
		}
		perToken := l.BucketRefillPer().Seconds() / float64(l.BucketRefillCount())
		need := 1.0 - tokens
		secs := math.Ceil(need * perToken)
		return Decision{Allowed: false, LimitType: string(l.Type), RetryAfter: time.Duration(secs) * time.Second}
	}
	return Decision{Allowed: true}
}

func applyStart(l workflow.Limit, st *state, now time.Time) {
	if l.Type != workflow.LimitBucket {
		return
	}
	tokens := currentTokens(l, st, now)
	st.BucketTokens = tokens - 1.0
	st.BucketUpdatedAt = now
	st.BucketInit = true
}

func currentTokens(l workflow.Limit, st *state, now time.Time) float64 {
	capacity := float64(l.BucketCapacity())
	if !st.BucketInit {
		return capacity
	}
	elapsed := now.Sub(st.BucketUpdatedAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	perSec := float64(l.BucketRefillCount()) / l.BucketRefillPer().Seconds()
	tokens := st.BucketTokens + elapsed*perSec
	if tokens > capacity {
		tokens = capacity
	}
	return tokens
}

func (m *Manager) load(name string) (*state, error) {
	p := m.path(name)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &state{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("limiter: read %s: %w", p, err)
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("limiter: decode %s: %w", p, err)
	}
	return &s, nil
}

func (m *Manager) save(name string, s *state) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("limiter: mkdir %s: %w", m.dir, err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	p := m.path(name)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("limiter: write %s: %w", tmp, err)
	}
	return os.Rename(tmp, p)
}

func (m *Manager) path(name string) string {
	return filepath.Join(m.dir, name+".json")
}

// Status is a read-only view of one limit's current standing.
type Status struct {
	Type       string
	Allowed    bool
	RetryAfter time.Duration
	// Tokens and Capacity are meaningful for bucket limits only.
	Tokens     float64
	Capacity   int
	LastFinish time.Time
	LastStatus string
}

// Inspect reports each declared limit's standing without mutating state.
func (m *Manager) Inspect(wf *workflow.Workflow, now time.Time) ([]Status, error) {
	if len(wf.Limits) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.load(wf.Name)
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(wf.Limits))
	for _, l := range wf.Limits {
		d := checkLimit(l, st, now)
		s := Status{
			Type:       string(l.Type),
			Allowed:    d.Allowed,
			RetryAfter: d.RetryAfter,
			LastFinish: st.CooldownLastFinishAt,
			LastStatus: st.CooldownLastFinishStatus,
		}
		if l.Type == workflow.LimitBucket {
			s.Tokens = currentTokens(l, st, now)
			s.Capacity = l.BucketCapacity()
		}
		out = append(out, s)
	}
	return out, nil
}

// Reset discards the persisted limit state for one workflow, so the next
// job is admitted as if the workflow had never run.
func (m *Manager) Reset(name string) error {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("limiter: invalid workflow name %q", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.Remove(m.path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("limiter: reset %s: %w", name, err)
	}
	return nil
}
