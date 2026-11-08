package workflow

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatchNestedDirectories(t *testing.T) {
	t.Run("existing nested directory", func(t *testing.T) {
		root := t.TempDir()
		nested := filepath.Join(root, "team", "prod")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		changes, stop := startWorkflowWatch(t, root)
		writeWatchFile(t, filepath.Join(nested, "deploy.yml"))
		waitWorkflowChange(t, changes)
		stop()
	})

	t.Run("new nested directory", func(t *testing.T) {
		root := t.TempDir()
		changes, stop := startWorkflowWatch(t, root)
		nested := filepath.Join(root, "team", "prod")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		waitWorkflowChange(t, changes)
		drainWorkflowChanges(changes)
		writeWatchFile(t, filepath.Join(nested, "deploy.yml"))
		waitWorkflowChange(t, changes)
		stop()
	})

	t.Run("removed nested directory", func(t *testing.T) {
		root := t.TempDir()
		changes, stop := startWorkflowWatch(t, root)
		nested := filepath.Join(root, "team", "prod")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		waitWorkflowChange(t, changes)
		drainWorkflowChanges(changes)
		if err := os.RemoveAll(filepath.Join(root, "team")); err != nil {
			t.Fatal(err)
		}
		waitWorkflowChange(t, changes)
		stop()
	})

	t.Run("renamed outside", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		changes, stop := startWorkflowWatch(t, root)
		nested := filepath.Join(root, "team")
		if err := os.Mkdir(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		waitWorkflowChange(t, changes)
		drainWorkflowChanges(changes)
		if err := os.Rename(nested, filepath.Join(outside, "team")); err != nil {
			t.Fatal(err)
		}
		waitWorkflowChange(t, changes)
		stop()
	})
}

func startWorkflowWatch(t *testing.T, dir string) (<-chan struct{}, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan struct{}, 8)
	errCh := make(chan error, 1)
	go func() { errCh <- Watch(ctx, dir, 40*time.Millisecond, changes) }()
	readyPath := filepath.Join(dir, "watch-ready.yml")
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	for {
		writeWatchFile(t, readyPath)
		select {
		case <-changes:
			drainWorkflowChanges(changes)
			goto ready
		case <-time.After(60 * time.Millisecond):
		case <-deadline.C:
			cancel()
			t.Fatal("timed out waiting for watcher readiness")
		}
	}

ready:
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("Watch: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("Watch did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return changes, stop
}

func writeWatchFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("name: watch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitWorkflowChange(t *testing.T, changes <-chan struct{}) {
	t.Helper()
	select {
	case <-changes:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for workflow change")
	}
}

func drainWorkflowChanges(changes <-chan struct{}) {
	for {
		select {
		case <-changes:
		default:
			return
		}
	}
}
