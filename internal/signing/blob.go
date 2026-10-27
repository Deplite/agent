package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"unicode"
)

// maxEd25519Blob caps how much of an artifact is buffered for Ed25519 keys.
// Ed25519 signs the whole message and Go offers no streaming API, so the
// bytes have to be held at once; ECDSA and RSA stream through a hash.
const maxEd25519Blob = 256 << 20

// ParsePublicKeyPEM decodes a PKIX public key in PEM form. Private keys
// and key types no signer here can verify are rejected.
func ParsePublicKeyPEM(publicKeyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("signing: no PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse public key: %w", err)
	}
	switch parsed.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return parsed, nil
	default:
		return nil, fmt.Errorf("signing: unsupported public key type %T", parsed)
	}
}

// PublicKeyID returns a short hex fingerprint over the key's DER form, so
// two PEM texts that differ only in whitespace compare equal.
func PublicKeyID(publicKeyPEM string) (string, error) {
	pub, err := ParsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("signing: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8]), nil
}

// VerifyBlobPEM verifies a `cosign sign-blob --key` signature over the file
// at path, without shelling out to cosign.
//
// cosign signs a digest for ECDSA and RSA keys but the raw message for
// Ed25519, so each key type is handed the bytes it was signed over.
func VerifyBlobPEM(publicKeyPEM, signatureBase64, path string) error {
	pub, err := ParsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return err
	}
	sig, err := decodeSignature(signatureBase64)
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		// cosign pairs the curve with its matching hash (P-384 → SHA-384,
		// P-521 → SHA-512). Releases signed by a cosign old enough to have
		// used SHA-256 for every curve still have to verify, so both digests
		// are computed in one pass and either one is accepted.
		curveHash := ecdsaHash(key)
		digests, err := digestStream(f, curveHash, crypto.SHA256)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(key, digests[0], sig) && !ecdsa.VerifyASN1(key, digests[1], sig) {
			return errors.New("signing: artifact signature verification failed (ECDSA)")
		}
	case *rsa.PublicKey:
		digests, err := digestStream(f, crypto.SHA256)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digests[0], sig); err != nil {
			return fmt.Errorf("signing: artifact signature verification failed (RSA PKCS#1 v1.5): %w", err)
		}
	case ed25519.PublicKey:
		msg, err := readCapped(f, maxEd25519Blob)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, msg, sig) {
			return errors.New("signing: artifact signature verification failed (Ed25519)")
		}
	}
	return nil
}

func ecdsaHash(pub *ecdsa.PublicKey) crypto.Hash {
	switch pub.Curve {
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// digestStream hashes r once with every requested algorithm, so a large
// artifact is read from disk a single time.
func digestStream(r io.Reader, hashes ...crypto.Hash) ([][]byte, error) {
	hashers := make([]hash.Hash, len(hashes))
	writers := make([]io.Writer, len(hashes))
	for i, h := range hashes {
		hashers[i] = h.New()
		writers[i] = hashers[i]
	}
	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}
	out := make([][]byte, len(hashers))
	for i, h := range hashers {
		out[i] = h.Sum(nil)
	}
	return out, nil
}

func readCapped(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("signing: artifact exceeds the %d MiB Ed25519 verification limit; sign it with an ECDSA or RSA key instead", limit>>20)
	}
	return buf.Bytes(), nil
}

// decodeSignature accepts cosign's standard base64 output, tolerating the
// line breaks a signature picks up when it travels through a text field.
func decodeSignature(s string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	if compact == "" {
		return nil, errors.New("signing: empty signature")
	}
	sig, err := base64.StdEncoding.DecodeString(compact)
	if err == nil {
		return sig, nil
	}
	sig, rawErr := base64.RawStdEncoding.DecodeString(compact)
	if rawErr != nil {
		return nil, fmt.Errorf("signing: decode signature: %w", err)
	}
	return sig, nil
}
