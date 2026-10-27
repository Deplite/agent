package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := newAppStore(dir)

	if _, ok := st.get("app1"); ok {
		t.Fatal("empty store should not find app1")
	}
	rec := appRecord{ReleaseID: "r1", Version: "1.0.0", Sequence: 3, Channel: "stable"}
	if err := st.put("app1", rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok := st.get("app1")
	if !ok || got != rec {
		t.Fatalf("get = %+v ok=%v, want %+v", got, ok, rec)
	}

	// Reload from disk with a fresh store.
	m, err := newAppStore(dir).load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m["app1"].ReleaseID != "r1" || m["app1"].Sequence != 3 {
		t.Fatalf("reloaded = %+v", m["app1"])
	}

	fi, err := os.Stat(filepath.Join(dir, "apps.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 600", perm)
	}
}

func TestAppStorePutIfAbsent(t *testing.T) {
	dir := t.TempDir()
	st := newAppStore(dir)

	seeded := appRecord{ReleaseID: "r1", Version: "1.0.0", Sequence: 1, Channel: "stable"}
	stored, err := st.putIfAbsent("app1", seeded)
	if err != nil || !stored {
		t.Fatalf("putIfAbsent on empty store: stored=%v err=%v", stored, err)
	}
	got, ok := st.get("app1")
	if !ok || got != seeded {
		t.Fatalf("get after putIfAbsent = %+v ok=%v, want %+v", got, ok, seeded)
	}

	newer := appRecord{ReleaseID: "r2", Version: "1.1.0", Sequence: 2, Channel: "stable"}
	stored, err = st.putIfAbsent("app1", newer)
	if err != nil || stored {
		t.Fatalf("putIfAbsent on existing record: stored=%v err=%v", stored, err)
	}
	got, ok = st.get("app1")
	if !ok || got != seeded {
		t.Fatalf("existing record should be unchanged: got %+v ok=%v, want %+v", got, ok, seeded)
	}
}

func TestParamInt64(t *testing.T) {
	if v, ok := paramInt64(float64(2)); !ok || v != 2 {
		t.Fatalf("float64: %d %v", v, ok)
	}
	if v, ok := paramInt64(json.Number("5")); !ok || v != 5 {
		t.Fatalf("json.Number: %d %v", v, ok)
	}
	if _, ok := paramInt64("nope"); ok {
		t.Fatal("string should not convert")
	}
	if _, ok := paramInt64(nil); ok {
		t.Fatal("nil should not convert")
	}
}
