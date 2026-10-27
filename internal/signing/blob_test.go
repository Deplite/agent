package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func publicKeyPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func writeBlob(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	return p
}

// signBlob mirrors what `cosign sign-blob --key` produces: ECDSA signs the
// digest its curve is paired with, RSA the SHA-256 digest, and Ed25519 the
// raw message.
func signBlob(t *testing.T, key crypto.PrivateKey, data []byte) string {
	t.Helper()
	var (
		sig []byte
		err error
	)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, hashWith(t, ecdsaHash(&k.PublicKey), data))
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hashWith(t, crypto.SHA256, data))
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, data)
	default:
		t.Fatalf("unsupported key type %T", key)
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func hashWith(t *testing.T, h crypto.Hash, data []byte) []byte {
	t.Helper()
	hasher := h.New()
	if _, err := hasher.Write(data); err != nil {
		t.Fatalf("hash: %v", err)
	}
	return hasher.Sum(nil)
}

func TestVerifyBlobPEM(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path := writeBlob(t, data)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	ec521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}

	cases := []struct {
		name string
		pub  crypto.PublicKey
		priv crypto.PrivateKey
	}{
		{"ecdsa-p256", &ec.PublicKey, ec},
		{"ecdsa-p384", &ec384.PublicKey, ec384},
		{"ecdsa-p521", &ec521.PublicKey, ec521},
		{"rsa-2048", &rsaKey.PublicKey, rsaKey},
		{"ed25519", edPub, edPriv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPEM := publicKeyPEM(t, tc.pub)
			sig := signBlob(t, tc.priv, data)

			if err := VerifyBlobPEM(keyPEM, sig, path); err != nil {
				t.Fatalf("valid signature should verify: %v", err)
			}
			if err := VerifyBlobPEM(keyPEM, sig, writeBlob(t, []byte("tampered"))); err == nil {
				t.Fatal("signature over other bytes should fail")
			}
			if err := VerifyBlobPEM(keyPEM, signBlob(t, tc.priv, []byte("other")), path); err == nil {
				t.Fatal("signature of a different payload should fail")
			}
		})
	}
}

// Older cosign hashed every ECDSA curve with SHA-256; those signatures still
// have to verify against a P-384 or P-521 key.
func TestVerifyBlobPEMAcceptsLegacyEcdsaHash(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path := writeBlob(t, data)

	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, key, hashWith(t, crypto.SHA256, data))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		encoded := base64.StdEncoding.EncodeToString(sig)
		if err := VerifyBlobPEM(publicKeyPEM(t, &key.PublicKey), encoded, path); err != nil {
			t.Fatalf("%s with a SHA-256 digest should verify: %v", curve.Params().Name, err)
		}
	}
}

func TestVerifyBlobPEMRejectsWrongKey(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path := writeBlob(t, data)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig := signBlob(t, signer, data)

	if err := VerifyBlobPEM(publicKeyPEM(t, &other.PublicKey), sig, path); err == nil {
		t.Fatal("a signature from another key should fail")
	}
}

func TestVerifyBlobPEMSignatureEncoding(t *testing.T) {
	data := []byte("deplite-artifact-bytes")
	path := writeBlob(t, data)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPEM := publicKeyPEM(t, &key.PublicKey)
	sig := signBlob(t, key, data)

	// Signatures pick up newlines when they travel through text fields.
	if err := VerifyBlobPEM(keyPEM, sig[:8]+"\n"+sig[8:]+"\n", path); err != nil {
		t.Fatalf("wrapped signature should verify: %v", err)
	}
	if err := VerifyBlobPEM(keyPEM, "", path); err == nil {
		t.Fatal("empty signature should fail")
	}
	if err := VerifyBlobPEM(keyPEM, "not base64!!", path); err == nil {
		t.Fatal("undecodable signature should fail")
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := ParsePublicKeyPEM(publicKeyPEM(t, &key.PublicKey)); err != nil {
		t.Fatalf("public key should parse: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := ParsePublicKeyPEM(privPEM); err == nil {
		t.Fatal("a private key should be rejected")
	}
	if _, err := ParsePublicKeyPEM("not a pem"); err == nil {
		t.Fatal("non-PEM input should be rejected")
	}
}

func TestPublicKeyIDIgnoresFormatting(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyPEM := publicKeyPEM(t, &key.PublicKey)

	id, err := PublicKeyID(keyPEM)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	padded, err := PublicKeyID("\n" + keyPEM + "\n")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if id != padded {
		t.Fatalf("surrounding whitespace changed the fingerprint: %q vs %q", id, padded)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	otherID, err := PublicKeyID(publicKeyPEM(t, &other.PublicKey))
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if id == otherID {
		t.Fatal("different keys should have different fingerprints")
	}
}
