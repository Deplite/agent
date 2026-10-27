package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyArtifactChecksum(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "art.bin")
	data := []byte("deplite-artifact-bytes")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])

	if err := verifyArtifactChecksum(p, hexsum); err != nil {
		t.Fatalf("matching checksum should pass: %v", err)
	}
	if err := verifyArtifactChecksum(p, strings.ToUpper(hexsum)); err != nil {
		t.Fatalf("checksum compare should be case-insensitive: %v", err)
	}
	if err := verifyArtifactChecksum(p, "deadbeef"); err == nil {
		t.Fatal("mismatched checksum should fail")
	}
}

func TestArtifactVerificationFor(t *testing.T) {
	fileRef := map[string]any{"__type": "FileRef", "id": "f1"}

	v, ok := artifactVerificationFor(map[string]any{
		"artifact":            fileRef,
		"checksum_sha256":     "abc",
		"signature":           "sig",
		"artifact_public_key": "pem",
		"application_id":      "app-1",
	})
	if !ok {
		t.Fatal("a FileRef artifact should be verified")
	}
	if v.checksum != "abc" || v.signature != "sig" || v.serverKeyPEM != "pem" || v.applicationID != "app-1" {
		t.Fatalf("params not read through: %+v", v)
	}

	if _, ok := artifactVerificationFor(map[string]any{"image": "reg/x@sha256:aa", "signature": "sig"}); ok {
		t.Fatal("an image release has no local artifact to verify")
	}
	if _, ok := artifactVerificationFor(nil); ok {
		t.Fatal("nil params should not be verified")
	}
}

type signingKey struct {
	priv   *ecdsa.PrivateKey
	pubPEM string
}

func newSigningKey(t *testing.T) signingKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return signingKey{priv: priv, pubPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func (k signingKey) sign(t *testing.T, data []byte) string {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// artifactFixture writes an artifact and returns its path plus a policy
// pointing at an empty key directory.
func artifactFixture(t *testing.T, data []byte) (string, artifactPolicy) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	return path, artifactPolicy{mode: verifyAuto, keyDir: filepath.Join(dir, "keys")}
}

func installKey(t *testing.T, p artifactPolicy, name, keyPEM string) string {
	t.Helper()
	if err := os.MkdirAll(p.keyDir, 0o700); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	path := filepath.Join(p.keyDir, name)
	if err := os.WriteFile(path, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestVerifyArtifactWithLocalKey(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	key := newSigningKey(t)
	keyPath := installKey(t, policy, fallbackKeyName, key.pubPEM)

	sum := sha256.Sum256(data)
	v := artifactVerification{
		checksum:  hex.EncodeToString(sum[:]),
		signature: key.sign(t, data),
	}
	res, err := verifyArtifact(path, v, policy)
	if err != nil {
		t.Fatalf("a signature made by the installed key should verify: %v", err)
	}
	if !strings.Contains(res.verifiedWith, keyPath) {
		t.Fatalf("result should name the key used: %+v", res)
	}
	if !res.signatureVerified() || !res.checksumVerified {
		t.Fatalf("both checks ran and should be reported to the workflow: %+v", res)
	}
	if len(res.warnings) != 0 {
		t.Fatalf("a clean verification should warn about nothing: %v", res.warnings)
	}

	// The whole point of the local key: an installed key makes a missing
	// signature a failure rather than a skipped check.
	v.signature = ""
	if _, err := verifyArtifact(path, v, policy); err == nil {
		t.Fatal("a missing signature should fail once a key is installed")
	}

	v.signature = newSigningKey(t).sign(t, data)
	if _, err := verifyArtifact(path, v, policy); err == nil {
		t.Fatal("a signature from another key should fail")
	}
}

func TestVerifyArtifactPrefersPerAppKey(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	appKey := newSigningKey(t)
	installKey(t, policy, fallbackKeyName, newSigningKey(t).pubPEM)
	appKeyPath := installKey(t, policy, "app-1.pub", appKey.pubPEM)

	v := artifactVerification{signature: appKey.sign(t, data), applicationID: "app-1"}
	res, err := verifyArtifact(path, v, policy)
	if err != nil {
		t.Fatalf("the per-app key should be used: %v", err)
	}
	if !strings.Contains(res.verifiedWith, appKeyPath) {
		t.Fatalf("result should name the per-app key: %+v", res)
	}
}

func TestVerifyArtifactKeyLookupStaysInKeyDir(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	key := newSigningKey(t)
	installKey(t, policy, fallbackKeyName, key.pubPEM)

	outside := filepath.Join(filepath.Dir(policy.keyDir), "escaped.pub")
	if err := os.WriteFile(outside, []byte(newSigningKey(t).pubPEM), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// application_id comes from the server, so it must not be able to point the
	// lookup at a file outside the key directory.
	v := artifactVerification{signature: key.sign(t, data), applicationID: "../escaped"}
	if _, err := verifyArtifact(path, v, policy); err != nil {
		t.Fatalf("lookup should have stayed in the key dir and used app.pub: %v", err)
	}
}

func TestVerifyArtifactServerKeyIsOptIn(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	key := newSigningKey(t)

	v := artifactVerification{signature: key.sign(t, data), serverKeyPEM: key.pubPEM}
	if _, err := verifyArtifact(path, v, policy); err == nil {
		t.Fatal("a signed release with no local key should fail without the opt-in")
	}

	policy.trustServer = true
	res, err := verifyArtifact(path, v, policy)
	if err != nil {
		t.Fatalf("the opt-in should allow the server key: %v", err)
	}
	if len(res.warnings) == 0 {
		t.Fatal("trusting the server key should be warned about")
	}
}

func TestVerifyArtifactWarnsOnKeyMismatch(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	local := newSigningKey(t)
	installKey(t, policy, fallbackKeyName, local.pubPEM)

	// A rotation in progress: the server already advertises the new key while
	// this device still holds the old one. The local key decides.
	v := artifactVerification{signature: local.sign(t, data), serverKeyPEM: newSigningKey(t).pubPEM}
	res, err := verifyArtifact(path, v, policy)
	if err != nil {
		t.Fatalf("the local key should still verify: %v", err)
	}
	if len(res.warnings) == 0 {
		t.Fatal("a key mismatch should be reported")
	}
}

func TestVerifyArtifactWithoutSignatureOrKey(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)

	res, err := verifyArtifact(path, artifactVerification{}, policy)
	if err != nil {
		t.Fatalf("an unsigned release should still deploy in auto mode: %v", err)
	}
	if len(res.warnings) == 0 {
		t.Fatal("deploying without verification should be logged as unverified")
	}
	// The workflow has to be able to tell this apart from a real verification,
	// otherwise it skips its own fallback check.
	if res.signatureVerified() || res.checksumVerified {
		t.Fatalf("nothing was verified and nothing should be claimed: %+v", res)
	}

	policy.mode = verifyRequire
	if _, err := verifyArtifact(path, artifactVerification{}, policy); err == nil {
		t.Fatal("require mode should refuse an unverifiable artifact")
	}
}

func TestVerifyArtifactChecksumRunsInEveryMode(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	policy.mode = verifyOff

	v := artifactVerification{checksum: strings.Repeat("a", 64)}
	if _, err := verifyArtifact(path, v, policy); err == nil {
		t.Fatal("a checksum mismatch should fail even with signature checks off")
	}

	sum := sha256.Sum256(data)
	v.checksum = hex.EncodeToString(sum[:])
	res, err := verifyArtifact(path, v, policy)
	if err != nil {
		t.Fatalf("off mode should skip only the signature: %v", err)
	}
	if !res.checksumVerified || res.signatureVerified() {
		t.Fatalf("off mode ran the checksum and nothing else: %+v", res)
	}
}

func TestVerifyArtifactRejectsUnusableKeyFile(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path, policy := artifactFixture(t, data)
	installKey(t, policy, fallbackKeyName, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n")

	// Falling back to "no key installed" here would quietly deploy unverified.
	if _, err := verifyArtifact(path, artifactVerification{}, policy); err == nil {
		t.Fatal("an unparseable key file should fail the job")
	}
}

func TestArtifactPolicyFromEnv(t *testing.T) {
	t.Setenv("DEPLITE_ARTIFACT_VERIFY", "")
	t.Setenv("DEPLITE_ARTIFACT_KEY_DIR", "")
	t.Setenv("DEPLITE_ARTIFACT_TRUST_SERVER_KEY", "")
	p := artifactPolicyFromEnv()
	if p.mode != verifyAuto || p.keyDir != defaultArtifactKeyDir || p.trustServer {
		t.Fatalf("unexpected defaults: %+v", p)
	}

	t.Setenv("DEPLITE_ARTIFACT_VERIFY", "nonsense")
	if got := artifactPolicyFromEnv().mode; got != verifyAuto {
		t.Fatalf("an unknown mode should fall back to auto, got %q", got)
	}

	t.Setenv("DEPLITE_ARTIFACT_VERIFY", "REQUIRE")
	t.Setenv("DEPLITE_ARTIFACT_KEY_DIR", "/srv/keys")
	t.Setenv("DEPLITE_ARTIFACT_TRUST_SERVER_KEY", "yes")
	p = artifactPolicyFromEnv()
	if p.mode != verifyRequire || p.keyDir != "/srv/keys" || !p.trustServer {
		t.Fatalf("unexpected policy: %+v", p)
	}
}
