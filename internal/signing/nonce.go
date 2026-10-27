package signing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("signing: read random bytes: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
