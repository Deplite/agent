package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yml")
	bad := filepath.Join(dir, "bad.yml")
	malformed := filepath.Join(dir, "malformed.yml")
	if err := os.WriteFile(good, []byte("name: hello\nsteps:\n  - name: greet\n    run: \"true\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("name: hello\nsteps:\n  - name: greet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformed, []byte("name: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	wf, err := LoadFile(good)
	if err != nil {
		t.Fatalf("LoadFile(good): %v", err)
	}
	if wf.Name != "hello" {
		t.Errorf("name = %q, want hello", wf.Name)
	}

	if _, err := LoadFile(bad); err == nil || !strings.Contains(err.Error(), "run") {
		t.Errorf("LoadFile(bad) = %v, want a validation error about run", err)
	}
	if _, err := LoadFile(malformed); err == nil {
		t.Error("LoadFile accepted malformed yaml")
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("LoadFile accepted a missing path")
	}
}
