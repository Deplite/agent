package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildCanonicalMatchesServerFormat(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	got := BuildCanonical(SignableRequest{
		Timestamp: "1717200000",
		Nonce:     "abc123",
		Method:    "post",
		Path:      "/v1/agent/heartbeat",
		Body:      body,
	})

	wantSum := sha256.Sum256(body)
	want := strings.Join([]string{
		"1717200000",
		"abc123",
		"POST",
		"/v1/agent/heartbeat",
		hex.EncodeToString(wantSum[:]),
	}, "\n")

	if string(got) != want {
		t.Fatalf("canonical mismatch\n got:  %q\n want: %q", got, want)
	}
}

func TestBuildCanonicalEmptyBody(t *testing.T) {
	got := BuildCanonical(SignableRequest{
		Timestamp: "1",
		Nonce:     "n",
		Method:    "GET",
		Path:      "/v1/agent/stream",
		Body:      nil,
	})
	emptyHash := sha256.Sum256(nil)
	want := "1\nn\nGET\n/v1/agent/stream\n" + hex.EncodeToString(emptyHash[:])
	if string(got) != want {
		t.Fatalf("empty-body canonical mismatch\n got:  %q\n want: %q", got, want)
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	message := BuildCanonical(SignableRequest{
		Timestamp: "1717200000",
		Nonce:     "n",
		Method:    "POST",
		Path:      "/v1/agent/heartbeat",
		Body:      []byte(``),
	})
	sig := kp.Sign(message)

	if !ed25519.Verify(kp.Public, message, sig) {
		t.Fatal("signature did not verify with the matching public key")
	}

	tampered := make([]byte, len(message))
	copy(tampered, message)
	tampered[0] ^= 0xff
	if ed25519.Verify(kp.Public, tampered, sig) {
		t.Fatal("signature verified against tampered message")
	}
}

func TestKeyPairPEMRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	privPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("private PEM: %v", err)
	}
	if _, err := kp.PublicKeyPEM(); err != nil {
		t.Fatalf("public PEM: %v", err)
	}
	restored, err := ParsePrivateKeyPEM([]byte(privPEM))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(restored.Private) != string(kp.Private) {
		t.Fatal("private key did not survive PEM round-trip")
	}
	if string(restored.Public) != string(kp.Public) {
		t.Fatal("public key did not survive PEM round-trip")
	}
}

func TestNonceUniqueAndHex(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		n, err := NewNonce()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		if len(n) != 32 {
			t.Fatalf("nonce length = %d, want 32 hex chars", len(n))
		}
		if _, ok := seen[n]; ok {
			t.Fatalf("duplicate nonce after %d iterations: %q", i, n)
		}
		seen[n] = struct{}{}
	}
}
