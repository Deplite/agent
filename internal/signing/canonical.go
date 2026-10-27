// Package signing implements the Ed25519 request signing scheme.
package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type SignableRequest struct {
	Timestamp string
	Nonce     string
	Method    string
	Path      string
	Body      []byte
}

func BuildCanonical(req SignableRequest) []byte {
	if req.Method == "" {
		req.Method = "GET"
	}
	digest := sha256.Sum256(req.Body)
	return []byte(strings.Join([]string{
		req.Timestamp,
		req.Nonce,
		strings.ToUpper(req.Method),
		req.Path,
		hex.EncodeToString(digest[:]),
	}, "\n"))
}

func SHA256Hex(body []byte) string {
	d := sha256.Sum256(body)
	return hex.EncodeToString(d[:])
}

type ErrInvalidPath struct{ Path string }

func (e *ErrInvalidPath) Error() string {
	return fmt.Sprintf("signing: path must not contain a query string: %q", e.Path)
}
