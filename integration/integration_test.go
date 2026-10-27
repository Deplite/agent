//go:build integration

// Integration tests against a real Deplite backend.
//
// Run with:
//
//	DEPLITE_INSTALL_CODE=<one-time install code> \
//	DEPLITE_BASE_URL=https://api.deplite.io/v1 \
//	go test -tags=integration ./integration/...
//
// The install code is consumed on the first run; tests create a
// throwaway data dir under t.TempDir() so the host's real agent
// credentials are never touched.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/credstore"
)

func TestEnrollAgainstRealBackend(t *testing.T) {
	code := os.Getenv("DEPLITE_INSTALL_CODE")
	if code == "" {
		t.Skip("DEPLITE_INSTALL_CODE not set; skipping integration test")
	}
	baseURL := os.Getenv("DEPLITE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.deplite.io/v1"
	}

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id, err := agent.Install(ctx, agent.InstallOptions{
		BaseURL:     baseURL,
		DataDir:     dir,
		InstallCode: code,
		Name:        "integration-test-" + time.Now().Format("20060102-150405"),
		Version:     "integration",
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if id.AgentID == "" || id.OrganizationID == "" {
		t.Fatalf("enroll response missing required fields: %+v", id)
	}

	store := credstore.New(dir)
	_, kp, err := store.Load()
	if err != nil {
		t.Fatalf("load creds: %v", err)
	}
	client := apiclient.New(id.BaseURL)
	signer := newSigner(id.AgentID, kp)

	if err := client.Heartbeat(ctx, signer); err != nil {
		t.Fatalf("heartbeat after enroll failed: %v", err)
	}
}
