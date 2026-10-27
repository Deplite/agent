package workflow

import (
	"context"
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
	if err := w.Add(dir); err != nil {
		return err
	}
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	var timer *time.Timer
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
			if !isWorkflowFile(ev.Name) {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(debounce, fire)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			return err
		}
	}
}

func isWorkflowFile(name string) bool {
	for _, ext := range []string{".yml", ".yaml"} {
		if len(name) > len(ext) && name[len(name)-len(ext):] == ext {
			return true
		}
	}
	return false
}
