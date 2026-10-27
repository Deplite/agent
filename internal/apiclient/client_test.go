package apiclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSigner satisfies the Signer interface with a fixed keypair so the
// server side can verify the signature.
type fakeSigner struct {
	id  string
	pub ed25519.PublicKey
	pri ed25519.PrivateKey
}

func (s *fakeSigner) AgentID() string           { return s.id }
func (s *fakeSigner) Sign(m []byte) []byte      { return ed25519.Sign(s.pri, m) }
func (s *fakeSigner) Public() ed25519.PublicKey { return s.pub }

func newFakeSigner(t *testing.T, id string) *fakeSigner {
	t.Helper()
	pub, pri, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &fakeSigner{id: id, pub: pub, pri: pri}
}

func TestSignedRequestProducesValidHeaders(t *testing.T) {
	signer := newFakeSigner(t, "agent-1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Headers must all be present.
		for _, h := range []string{"x-agent-id", "x-timestamp", "x-nonce", "x-signature"} {
			if r.Header.Get(h) == "" {
				t.Errorf("missing header %s", h)
			}
		}
		if got := r.Header.Get("x-agent-id"); got != "agent-1" {
			t.Errorf("agent id = %q, want agent-1", got)
		}
		// Timestamp must be a recent unix second.
		ts, err := strconv.ParseInt(r.Header.Get("x-timestamp"), 10, 64)
		if err != nil {
			t.Errorf("timestamp not numeric: %v", err)
		}
		if delta := time.Now().Unix() - ts; delta < 0 || delta > 5 {
			t.Errorf("timestamp skew %d s outside [0,5]", delta)
		}

		body, _ := io.ReadAll(r.Body)
		bodyHash := sha256.Sum256(body)
		canonical := strings.Join([]string{
			r.Header.Get("x-timestamp"),
			r.Header.Get("x-nonce"),
			r.Method,
			r.URL.Path,
			hex.EncodeToString(bodyHash[:]),
		}, "\n")
		sig, err := base64.StdEncoding.DecodeString(r.Header.Get("x-signature"))
		if err != nil {
			t.Errorf("decode signature: %v", err)
		}
		if !ed25519.Verify(signer.Public(), []byte(canonical), sig) {
			t.Errorf("server-side verify failed")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	var resp struct {
		OK bool `json:"ok"`
	}
	err := c.SignedRequest(context.Background(), signer, "POST", "/agent/heartbeat", nil, &resp)
	if err != nil {
		t.Fatalf("signed request: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response not decoded: %+v", resp)
	}
}

func TestHeartbeatProbeSendsSignedProbeID(t *testing.T) {
	signer := newFakeSigner(t, "agent-probe")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Method + " " + r.URL.Path; got != "POST /agent/heartbeat" {
			t.Errorf("request = %q, want POST /agent/heartbeat", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var got struct {
			ProbeID string `json:"probeId"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got.ProbeID != "probe-123" {
			t.Errorf("probeId = %q, want probe-123", got.ProbeID)
		}
		digest := sha256.Sum256(body)
		canonical := strings.Join([]string{
			r.Header.Get("x-timestamp"),
			r.Header.Get("x-nonce"),
			r.Method,
			r.URL.Path,
			hex.EncodeToString(digest[:]),
		}, "\n")
		sig, err := base64.StdEncoding.DecodeString(r.Header.Get("x-signature"))
		if err != nil {
			t.Errorf("decode signature: %v", err)
		}
		if !ed25519.Verify(signer.Public(), []byte(canonical), sig) {
			t.Errorf("probe heartbeat signature verification failed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	if err := New(srv.URL).HeartbeatProbe(context.Background(), signer, "probe-123"); err != nil {
		t.Fatalf("heartbeat probe: %v", err)
	}
}

func TestBearerRequestSendsAuthorizationHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer install-xyz" {
			t.Errorf("authz header = %q", got)
		}
		var body EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name != "ci-1" {
			t.Errorf("body.name = %q, want ci-1", body.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agentId":"a","organizationId":"o","serverPublicKey":"k"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	res, err := c.Enroll(context.Background(), "install-xyz", EnrollRequest{
		Name:      "ci-1",
		PublicKey: "PEM",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.AgentID != "a" || res.OrganizationID != "o" || res.ServerPublicKeyPEM != "k" {
		t.Fatalf("decoded enroll response wrong: %+v", res)
	}
}

func TestNon2xxBecomesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"bad code"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	_, err := c.Enroll(context.Background(), "x", EnrollRequest{Name: "x", PublicKey: "x"})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("err type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", apiErr.StatusCode)
	}
}
