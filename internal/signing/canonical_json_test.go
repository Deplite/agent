package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJSONMatchesServerStringify(t *testing.T) {
	in := map[string]any{
		"b": 1,
		"a": "hi",
		"c": []any{3, 2, 1},
		"d": map[string]any{"y": true, "x": nil},
	}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"a":"hi","b":1,"c":[3,2,1],"d":{"x":null,"y":true}}`
	if string(got) != want {
		t.Fatalf("\n got:  %s\n want: %s", got, want)
	}
}

// TestCanonicalJSONEscapesHTML locks the fix: <, >, and & now escape to
// their \uXXXX forms (matching the backend), rather than staying literal.
// Go's encoding/json default escaping is the oracle.
func TestCanonicalJSONEscapesHTML(t *testing.T) {
	in := map[string]any{
		"reason": "deploy <main> & rollback if >50% err",
		"ref":    "refs/heads/feature/<x>",
	}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want, _ := json.Marshal(in) // key-sorted, compact, default HTML escaping
	if string(got) != string(want) {
		t.Fatalf("\n got:  %s\n want: %s", got, want)
	}
	// The literal special characters must NOT survive unescaped.
	for _, bad := range []string{"<main>", "feature/<x>", "err & rollback"} {
		if strings.Contains(string(got), bad) {
			t.Fatalf("unescaped %q found in %s", bad, got)
		}
	}
}

// TestCanonicalJSONEscapingVectors pins the string-escaping bytes to Go's
// encoding/json default: a&b -> "a&b", <x> -> "<x>",
// U+2028 -> " ".
func TestCanonicalJSONEscapingVectors(t *testing.T) {
	for _, in := range []string{"a&b", "<x>", string(rune(0x2028)), string(rune(0x2029))} {
		got, err := CanonicalJSON(in)
		if err != nil {
			t.Fatalf("canonical(%q): %v", in, err)
		}
		want, _ := json.Marshal(in)
		if string(got) != string(want) {
			t.Fatalf("canonical(%q)\n got:  %s\n want: %s", in, got, want)
		}
	}
}

// A presigned download URL's ampersand separators must escape so the
// canonical bytes match what the backend signed.
func TestCanonicalJSONEscapesPresignedURL(t *testing.T) {
	in := map[string]any{"downloadUrl": "https://s3/x?sig=abc&exp=123&k=v"}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want, _ := json.Marshal(in)
	if string(got) != string(want) {
		t.Fatalf("\n got:  %s\n want: %s", got, want)
	}
	if strings.Contains(string(got), "abc&exp") {
		t.Fatalf("ampersand left unescaped in %s", got)
	}
}

func TestVerifyEd25519PEMRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	pem, err := kp.PublicKeyPEM()
	if err != nil {
		t.Fatalf("pem: %v", err)
	}
	msg := []byte("hello")
	sig := ed25519.Sign(kp.Private, msg)
	if err := VerifyEd25519PEM(pem, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyEd25519PEM(pem, []byte("tampered"), sig); err == nil {
		t.Fatal("expected error on tampered message")
	}
	bad := base64.StdEncoding.EncodeToString([]byte("not-pem"))
	if err := VerifyEd25519PEM(bad, msg, sig); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
}
