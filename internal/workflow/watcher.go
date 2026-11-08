package workflow

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch fires on out (debounced) whenever a *.yml / *.yaml file in dir
// is created, modified, removed, or renamed. Returns immediately if
// dir does not exist or fsnotify is unavailable; the agent still
// reports on the server-initiated sync_workflows event in that case.
func Watch(ctx context.Context, dir string, debounce time.Duration, out chan<- struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	watched := map[string]bool{}
	if err := addTree(w, dir, watched, true); err != nil {
		return err
	}
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	fire := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			name := filepath.Clean(ev.Name)
			if ev.Op&fsnotify.Create != 0 {
				info, err := os.Lstat(name)
				if err == nil && info.IsDir() {
					_ = addTree(w, name, watched, false)
					resetTimer(&timer, debounce, fire)
					continue
				}
			}
			if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 && watched[name] {
				removeTree(w, name, watched)
				resetTimer(&timer, debounce, fire)
				continue
			}
			if isWorkflowFile(name) {
				resetTimer(&timer, debounce, fire)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			return err
		}
	}
}

func addTree(w *fsnotify.Watcher, dir string, watched map[string]bool, requireRoot bool) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				return err
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		if err := w.Add(path); err != nil {
			if requireRoot && path == dir {
				return err
			}
		} else if watched != nil {
			watched[filepath.Clean(path)] = true
		}
		return nil
	})
}

func removeTree(w *fsnotify.Watcher, dir string, watched map[string]bool) {
	dir = filepath.Clean(dir)
	for path := range watched {
		if path == dir || withinDir(dir, path) {
			_ = w.Remove(path)
			delete(watched, path)
		}
	}
}

func withinDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resetTimer(timer **time.Timer, debounce time.Duration, fire func()) {
	if *timer != nil {
		(*timer).Stop()
	}
	*timer = time.AfterFunc(debounce, fire)
}

func isWorkflowFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yml", ".yaml":
		return true
	default:
		return false
	}
}
