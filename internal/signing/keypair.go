package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: generate keypair: %w", err)
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

func (k KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(k.Private, message)
}

func (k KeyPair) PublicKeyPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return "", fmt.Errorf("signing: marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func (k KeyPair) PrivateKeyPEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return "", fmt.Errorf("signing: marshal private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func ParsePrivateKeyPEM(pemBytes []byte) (KeyPair, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return KeyPair{}, errors.New("signing: no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: parse PKCS#8: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return KeyPair{}, fmt.Errorf("signing: PEM holds %T, not ed25519.PrivateKey", parsed)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return KeyPair{}, errors.New("signing: cannot derive public key")
	}
	return KeyPair{Public: pub, Private: priv}, nil
}
