package apiclient

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Deplite/agent/internal/signing"
)

// signDeploy builds a deploy envelope the way the backend does: the payload
// bytes are signed via their canonical form (default HTML escaping), and the
// same raw bytes travel in the envelope.
func signDeploy(t *testing.T, kp signing.KeyPair, payload map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	canonical, err := signing.CanonicalJSON(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(kp.Sign(canonical))
	env, err := json.Marshal(map[string]any{"payload": json.RawMessage(raw), "signature": sig})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return env
}

func TestParseAndVerifyDeployHappyPath(t *testing.T) {
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	serverPub, err := kp.PublicKeyPEM()
	if err != nil {
		t.Fatalf("pub: %v", err)
	}

	env := signDeploy(t, kp, map[string]any{
		"job_id":        "j-1",
		"workflow_name": "build",
		"debug":         false,
		"ref":           "main",
		"params":        map[string]any{"foo": "bar"},
		"issued_at":     1717200000,
		"nonce":         "n",
	})
	got, err := ParseAndVerifyDeploy(env, serverPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JobID != "j-1" || got.WorkflowName != "build" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestParseAndVerifyDeployRetainsRawParamsAndApproval(t *testing.T) {
	kp, _ := signing.GenerateKeyPair()
	serverPub, _ := kp.PublicKeyPEM()
	rawParams := json.RawMessage(`{"count":1.0,"text":"x"}`)
	rawApproval := json.RawMessage(`{"method":"hmac","keyId":"k"}`)
	payload := json.RawMessage(`{"job_id":"j-raw","workflow_name":"build","issued_at":1,"nonce":"n","params":{"count":1.0,"text":"x"},"approval":{"method":"hmac","keyId":"k"}}`)
	canonical, err := signing.CanonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payload":   payload,
		"signature": base64.StdEncoding.EncodeToString(kp.Sign(canonical)),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAndVerifyDeploy(env, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ParamsRaw) != string(rawParams) || string(got.Approval) != string(rawApproval) {
		t.Fatalf("raw fields = %s / %s", got.ParamsRaw, got.Approval)
	}
}

// An unknown extra field must not break verification: signing runs over the
// raw bytes, so fields this agent does not model still survive into the
// signed message.
func TestParseAndVerifyDeployToleratesUnknownField(t *testing.T) {
	kp, _ := signing.GenerateKeyPair()
	serverPub, _ := kp.PublicKeyPEM()

	env := signDeploy(t, kp, map[string]any{
		"job_id":        "j-2",
		"workflow_name": "build",
		"issued_at":     1,
		"nonce":         "n",
		"future_field":  "surprise",
	})
	got, err := ParseAndVerifyDeploy(env, serverPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JobID != "j-2" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

// A params value carrying a presigned URL with ampersands must verify: the
// canonical form escapes them, matching what the backend signed.
func TestParseAndVerifyDeployWithPresignedURL(t *testing.T) {
	kp, _ := signing.GenerateKeyPair()
	serverPub, _ := kp.PublicKeyPEM()

	env := signDeploy(t, kp, map[string]any{
		"job_id":        "j-3",
		"workflow_name": "app-update",
		"issued_at":     1,
		"nonce":         "n",
		"params": map[string]any{
			"artifact": map[string]any{
				"__type":      "FileRef",
				"id":          "f1",
				"downloadUrl": "https://s3.example/x?sig=abc&exp=123&k=v",
			},
			"checksum_sha256": "deadbeef",
		},
	})
	got, err := ParseAndVerifyDeploy(env, serverPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JobID != "j-3" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestParseAndVerifyDeployRejectsTampered(t *testing.T) {
	kp, _ := signing.GenerateKeyPair()
	serverPub, _ := kp.PublicKeyPEM()

	raw, _ := json.Marshal(map[string]any{"job_id": "j", "workflow_name": "w", "issued_at": 1, "nonce": "n"})
	canonical, _ := signing.CanonicalJSON(json.RawMessage(raw))
	sig := base64.StdEncoding.EncodeToString(kp.Sign(canonical))

	// Ship a different payload under the signature of the original.
	tampered, _ := json.Marshal(map[string]any{"job_id": "j", "workflow_name": "evil", "issued_at": 1, "nonce": "n"})
	env, _ := json.Marshal(map[string]any{"payload": json.RawMessage(tampered), "signature": sig})

	if _, err := ParseAndVerifyDeploy(env, serverPub); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestParseAndVerifyDeployRejectsMissingSignature(t *testing.T) {
	kp, _ := signing.GenerateKeyPair()
	serverPub, _ := kp.PublicKeyPEM()
	env, _ := json.Marshal(map[string]any{"payload": json.RawMessage(`{"job_id":"j"}`), "signature": ""})
	if _, err := ParseAndVerifyDeploy(env, serverPub); err == nil {
		t.Fatal("expected error for missing signature")
	}
}
