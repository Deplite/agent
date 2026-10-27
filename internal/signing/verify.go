package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// VerifyEd25519PEM verifies sig over message using a PKIX-encoded
// Ed25519 public key in PEM form. Returns nil on success.
func VerifyEd25519PEM(publicKeyPEM string, message, sig []byte) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("signing: no PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("signing: parse public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("signing: PEM holds %T, not ed25519.PublicKey", parsed)
	}
	if !ed25519.Verify(pub, message, sig) {
		return errors.New("signing: signature verification failed")
	}
	return nil
}
