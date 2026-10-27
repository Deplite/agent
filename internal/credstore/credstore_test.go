package credstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Deplite/agent/internal/signing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := New(dir)

	if store.Exists() {
		t.Fatal("Exists() should be false on a fresh dir")
	}

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	id := Identity{
		AgentID:            "00000000-0000-0000-0000-000000000001",
		OrganizationID:     "00000000-0000-0000-0000-0000000000aa",
		BaseURL:            "https://api.deplite.io/v1",
		ServerPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n",
	}
	if err := store.Save(id, kp); err != nil {
		t.Fatalf("save: %v", err)
	}

	if !store.Exists() {
		t.Fatal("Exists() should be true after Save")
	}

	gotID, gotKP, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotID != id {
		t.Fatalf("identity mismatch\n got:  %+v\n want: %+v", gotID, id)
	}
	if string(gotKP.Private) != string(kp.Private) {
		t.Fatal("private key changed across save/load")
	}
}

func TestSaveSetsRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	store := New(dir)
	kp, _ := signing.GenerateKeyPair()
	if err := store.Save(Identity{AgentID: "a", BaseURL: "b"}, kp); err != nil {
		t.Fatalf("save: %v", err)
	}
	for _, name := range []string{identityFile, keyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != filePerm {
			t.Fatalf("%s perm = %o, want %o", name, info.Mode().Perm(), filePerm)
		}
	}
}

func TestLoadOnEmptyDir(t *testing.T) {
	store := New(t.TempDir())
	if _, _, err := store.Load(); err == nil {
		t.Fatal("Load on empty dir should error")
	}
}
