// Package credstore persists the agent identity and Ed25519 private key
// under <dir>/{identity.json, agent.key}. Files are 0600, dir is 0700.
package credstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Deplite/agent/internal/signing"
)

const (
	identityFile = "identity.json"
	keyFile      = "agent.key"
	dirPerm      = 0o700
	filePerm     = 0o600

	// Legacy filenames written by the internal reference agent. Read-only
	// here: when the dir holds these but no identity.json, Load() converts
	// them to the canonical layout on first read so existing operators do
	// not have to re-enroll.
	legacyAgentIDFile   = "agent.id"
	legacyServerPubFile = "server.pub"
)

type Identity struct {
	AgentID            string `json:"agentId"`
	OrganizationID     string `json:"organizationId"`
	BaseURL            string `json:"baseUrl"`
	ServerPublicKeyPEM string `json:"serverPublicKeyPem"`
}

type Store struct {
	Dir string
}

func New(dir string) *Store { return &Store{Dir: dir} }

// Exists reports whether either the canonical or the legacy layout is
// present. A half-written dir counts as "not exists" so a re-install
// can recover.
func (s *Store) Exists() bool {
	if _, err := os.Stat(filepath.Join(s.Dir, keyFile)); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(s.Dir, identityFile)); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(s.Dir, legacyAgentIDFile)); err == nil {
		return true
	}
	return false
}

func (s *Store) Save(id Identity, kp signing.KeyPair) error {
	if err := os.MkdirAll(s.Dir, dirPerm); err != nil {
		return fmt.Errorf("credstore: create dir: %w", err)
	}
	idBytes, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("credstore: marshal identity: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(s.Dir, identityFile), idBytes); err != nil {
		return err
	}
	keyPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("credstore: encode private key: %w", err)
	}
	return writeFileAtomic(filepath.Join(s.Dir, keyFile), []byte(keyPEM))
}

func (s *Store) Load() (Identity, signing.KeyPair, error) {
	if _, err := os.Stat(filepath.Join(s.Dir, identityFile)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, lerr := os.Stat(filepath.Join(s.Dir, legacyAgentIDFile)); lerr == nil {
				if cerr := s.convertLegacy(); cerr != nil {
					return Identity{}, signing.KeyPair{}, cerr
				}
			}
		}
	}

	idBytes, err := os.ReadFile(filepath.Join(s.Dir, identityFile))
	if err != nil {
		return Identity{}, signing.KeyPair{}, fmt.Errorf("credstore: read identity: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(idBytes, &id); err != nil {
		return Identity{}, signing.KeyPair{}, fmt.Errorf("credstore: parse identity: %w", err)
	}
	if id.AgentID == "" || id.BaseURL == "" {
		return Identity{}, signing.KeyPair{}, errors.New("credstore: identity.json missing agentId or baseUrl")
	}
	keyBytes, err := os.ReadFile(filepath.Join(s.Dir, keyFile))
	if err != nil {
		return Identity{}, signing.KeyPair{}, fmt.Errorf("credstore: read private key: %w", err)
	}
	kp, err := signing.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return Identity{}, signing.KeyPair{}, err
	}
	return id, kp, nil
}

// convertLegacy reads the reference agent's per-file layout
// (agent.id + server.pub) and writes a canonical identity.json. The
// agent.key file is shared between layouts so it stays as-is.
// baseUrl is taken from DEPLITE_BASE_URL or the public default.
func (s *Store) convertLegacy() error {
	idBytes, err := os.ReadFile(filepath.Join(s.Dir, legacyAgentIDFile))
	if err != nil {
		return fmt.Errorf("credstore: read legacy %s: %w", legacyAgentIDFile, err)
	}
	pubBytes, err := os.ReadFile(filepath.Join(s.Dir, legacyServerPubFile))
	if err != nil {
		return fmt.Errorf("credstore: read legacy %s: %w", legacyServerPubFile, err)
	}
	baseURL := os.Getenv("DEPLITE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.deplite.io/v1"
	}
	id := Identity{
		AgentID:            string(trimSpace(idBytes)),
		BaseURL:            baseURL,
		ServerPublicKeyPEM: string(pubBytes),
	}
	if id.AgentID == "" {
		return fmt.Errorf("credstore: legacy %s is empty", legacyAgentIDFile)
	}
	out, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.Dir, identityFile), out)
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end {
		c := b[start]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			start++
			continue
		}
		break
	}
	for end > start {
		c := b[end-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			end--
			continue
		}
		break
	}
	return b[start:end]
}

// writeFileAtomic uses rename(2) so a crash never leaves a half-written
// credential in place.
func writeFileAtomic(path string, data []byte) error {
	dir, base := filepath.Split(path)
	tmp, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return fmt.Errorf("credstore: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credstore: write temp: %w", err)
	}
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credstore: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("credstore: close temp: %w", err)
	}
	return os.Rename(tmpName, path)
}
