// Package mask redacts secret values from log lines.
package mask

import (
	"sort"
	"strings"
	"sync"
)

const redacted = "[REDACTED]"

type Masker struct {
	mu     sync.RWMutex
	values []string // kept sorted by length desc so longer secrets are replaced first
}

func New() *Masker { return &Masker{} }

// Add records a secret value to redact from later Apply calls. Empty
// and whitespace-only strings are ignored so an unset env var does not
// turn every blank into [REDACTED].
func (m *Masker) Add(value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.values {
		if v == value {
			return
		}
	}
	m.values = append(m.values, value)
	// Longer first so that "hunter" being a registered secret does not
	// partially redact a longer secret "hunter2" and leak the suffix.
	sort.Slice(m.values, func(i, j int) bool {
		return len(m.values[i]) > len(m.values[j])
	})
}

func (m *Masker) Apply(s string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := s
	for _, v := range m.values {
		out = strings.ReplaceAll(out, v, redacted)
	}
	return out
}

// Reset drops every previously registered secret. Used between jobs
// so values declared in one workflow do not leak masking into another.
func (m *Masker) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values = m.values[:0]
}
