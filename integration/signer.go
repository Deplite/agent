//go:build integration

package integration

import "github.com/Deplite/agent/internal/signing"

// keyPairSigner is a duplicate of the unexported signer in
// internal/agent. We re-declare it here so the integration test does
// not require touching the production package's visibility.
type keyPairSigner struct {
	id string
	kp signing.KeyPair
}

func newSigner(id string, kp signing.KeyPair) *keyPairSigner {
	return &keyPairSigner{id: id, kp: kp}
}

func (s *keyPairSigner) AgentID() string      { return s.id }
func (s *keyPairSigner) Sign(m []byte) []byte { return s.kp.Sign(m) }
