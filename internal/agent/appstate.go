package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// appRecord is the observed installed release of one application.
type appRecord struct {
	ReleaseID string `json:"releaseId"`
	Version   string `json:"version"`
	Sequence  int64  `json:"sequence"`
	Channel   string `json:"channel"`
}

// appStore persists observed per-application state at <dataDir>/apps.json.
type appStore struct {
	mu   sync.Mutex
	path string
}

func newAppStore(dataDir string) *appStore {
	return &appStore{path: filepath.Join(dataDir, "apps.json")}
}

func (s *appStore) load() (map[string]appRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *appStore) get(appID string) (appRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return appRecord{}, false
	}
	r, ok := m[appID]
	return r, ok
}

func (s *appStore) put(appID string, rec appRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return err
	}
	m[appID] = rec
	return s.saveLocked(m)
}

// putIfAbsent stores rec for appID only if no record exists yet, checking
// and writing under one lock so it can't clobber a concurrent put (e.g. a
// just-finished OTA job) with a stale value. Returns whether it stored.
func (s *appStore) putIfAbsent(appID string, rec appRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return false, err
	}
	if _, ok := m[appID]; ok {
		return false, nil
	}
	m[appID] = rec
	return true, s.saveLocked(m)
}

func (s *appStore) loadLocked() (map[string]appRecord, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]appRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]appRecord{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *appStore) saveLocked(m map[string]appRecord) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b)
}

// writeFileAtomic writes via a temp file and rename so a crash never leaves
// apps.json half-written. File 0600, dir 0700.
func writeFileAtomic(path string, data []byte) error {
	dir, base := filepath.Split(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
