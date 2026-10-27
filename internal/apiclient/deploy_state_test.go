package apiclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Deplite/agent/internal/signing"
)

// signManifest mirrors the backend: sign the canonical form of the raw
// payload bytes and ship those same bytes.
func signManifest(t *testing.T, kp signing.KeyPair, payload map[string]any) desiredManifest {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	canonical, err := signing.CanonicalJSON(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(kp.Sign(canonical))
	return desiredManifest{Payload: json.RawMessage(raw), Signature: sig}
}

func TestGetDesiredDeploysVerifies(t *testing.T) {
	agent := newFakeSigner(t, "a1")
	serverKP, _ := signing.GenerateKeyPair()
	serverPub, _ := serverKP.PublicKeyPEM()

	good := signManifest(t, serverKP, map[string]any{
		"application_id":  "app1",
		"slug":            "kiosk",
		"channel":         "stable",
		"update_workflow": "app-update",
		"current":         map[string]any{"release_id": "r1", "version": "1.1.0", "sequence": 1},
		"desired":         nil,
		"min_version":     "1.2.0",
		"min_sequence":    2,
		"forced":          true,
		"issued_at":       1750000000,
		"nonce":           "n1",
	})

	// Tampered: valid signature over one payload, a different payload shipped.
	tampered := signManifest(t, serverKP, map[string]any{"application_id": "app2", "nonce": "n2"})
	tampered.Payload = json.RawMessage(`{"application_id":"app2-evil","nonce":"n2"}`)

	// Empty signature must be rejected.
	empty := signManifest(t, serverKP, map[string]any{"application_id": "app3", "nonce": "n3"})
	empty.Signature = ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/agent/deploy/desired" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("x-signature") == "" {
			t.Errorf("missing agent signature header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(desiredResponse{Apps: []desiredManifest{good, tampered, empty}})
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	apps, err := c.GetDesiredDeploys(context.Background(), agent, serverPub)
	if err == nil {
		t.Fatal("expected non-nil error surfacing skipped manifests")
	}
	if len(apps) != 1 {
		t.Fatalf("verified apps = %d, want 1", len(apps))
	}
	if apps[0].ApplicationID != "app1" {
		t.Fatalf("app id = %q", apps[0].ApplicationID)
	}
	if apps[0].Current == nil || apps[0].Current.Sequence != 1 {
		t.Fatalf("current not decoded: %+v", apps[0].Current)
	}
	if apps[0].Desired != nil {
		t.Fatalf("desired should be nil, got %+v", apps[0].Desired)
	}
	if !apps[0].Forced || apps[0].MinSequence != 2 {
		t.Fatalf("scalar fields wrong: %+v", apps[0])
	}
}

func TestReportDeviceState(t *testing.T) {
	agent := newFakeSigner(t, "a1")
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/agent/deploy/report" {
			t.Errorf("path = %s", r.URL.Path)
		}
		for _, h := range []string{"x-agent-id", "x-timestamp", "x-nonce", "x-signature"} {
			if r.Header.Get(h) == "" {
				t.Errorf("missing header %s", h)
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	seq := int64(2)
	err := c.ReportDeviceState(context.Background(), agent, DeviceReport{
		ApplicationID:    "app1",
		CurrentReleaseID: "r1",
		CurrentSequence:  &seq,
		State:            DeviceIdle,
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if gotBody["applicationId"] != "app1" {
		t.Errorf("applicationId = %v", gotBody["applicationId"])
	}
	if gotBody["currentReleaseId"] != "r1" {
		t.Errorf("currentReleaseId = %v", gotBody["currentReleaseId"])
	}
	if gotBody["currentSequence"] != float64(2) {
		t.Errorf("currentSequence = %v", gotBody["currentSequence"])
	}
	if gotBody["state"] != "idle" {
		t.Errorf("state = %v", gotBody["state"])
	}
	if _, ok := gotBody["currentVersion"]; ok {
		t.Errorf("currentVersion should be omitted")
	}
	if _, ok := gotBody["error"]; ok {
		t.Errorf("error should be omitted")
	}
}
