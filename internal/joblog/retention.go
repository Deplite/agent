package joblog

import (
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LocalDir is where the shipper mirrors per-job logs on disk. Empty
// disables local persistence. Set by Start from DEPLITE_LOG_DIR.
var LocalDir string

// EnforceRetention prunes job log directories under LocalDir, keeping
// the n most recently modified. No-op if LocalDir is unset or n <= 0.
func EnforceRetention(n int) {
	if LocalDir == "" || n <= 0 {
		return
	}
	entries, err := os.ReadDir(LocalDir)
	if err != nil {
		return
	}
	type ent struct {
		name string
		mod  time.Time
	}
	dirs := make([]ent, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		dirs = append(dirs, ent{e.Name(), info.ModTime()})
	}
	if len(dirs) <= n {
		return
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod.Before(dirs[j].mod) })
	for i := 0; i < len(dirs)-n; i++ {
		_ = os.RemoveAll(filepath.Join(LocalDir, dirs[i].name))
	}
}
