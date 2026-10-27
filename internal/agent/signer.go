// Package agent drives enrollment and the long-lived agent loop.
package agent

import "github.com/Deplite/agent/internal/signing"

type keyPairSigner struct {
	id string
	kp signing.KeyPair
}

func newSigner(id string, kp signing.KeyPair) *keyPairSigner {
	return &keyPairSigner{id: id, kp: kp}
}

func (s *keyPairSigner) AgentID() string      { return s.id }
func (s *keyPairSigner) Sign(m []byte) []byte { return s.kp.Sign(m) }
