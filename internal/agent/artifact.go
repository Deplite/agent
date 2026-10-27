package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Deplite/agent/internal/files"
	"github.com/Deplite/agent/internal/signing"
)

// defaultArtifactKeyDir holds the public keys this device trusts to have
// signed an OTA artifact. It is the one input to verification the backend
// cannot reach, which is what makes the check worth running.
const defaultArtifactKeyDir = "/etc/deplite/keys"

// fallbackKeyName is used when the update job does not say which app it is
// for, which is the common single-app case.
const fallbackKeyName = "app.pub"

// Artifact verification modes, set with DEPLITE_ARTIFACT_VERIFY.
const (
	// verifyAuto lets the presence of a local public key decide: with one
	// installed a valid signature is mandatory, without one an unsigned
	// release still deploys and is logged as unverified.
	verifyAuto = "auto"
	// verifyRequire refuses to deploy anything this device cannot verify.
	verifyRequire = "require"
	// verifyOff skips signature checks entirely. Checksums still run.
	verifyOff = "off"
)

type artifactPolicy struct {
	mode        string
	keyDir      string
	trustServer bool
}

func artifactPolicyFromEnv() artifactPolicy {
	p := artifactPolicy{
		mode:        strings.ToLower(strings.TrimSpace(os.Getenv("DEPLITE_ARTIFACT_VERIFY"))),
		keyDir:      os.Getenv("DEPLITE_ARTIFACT_KEY_DIR"),
		trustServer: truthy(os.Getenv("DEPLITE_ARTIFACT_TRUST_SERVER_KEY")),
	}
	switch p.mode {
	case verifyAuto, verifyRequire, verifyOff:
	default:
		p.mode = verifyAuto
	}
	if p.keyDir == "" {
		p.keyDir = defaultArtifactKeyDir
	}
	return p
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// artifactVerification is what an OTA job must check before its workflow
// runs. It is read from the job params before the FileRef is rewritten into
// a local path.
type artifactVerification struct {
	checksum      string
	signature     string
	serverKeyPEM  string
	applicationID string
}

// artifactVerificationFor returns the checks owed by params, and false when
// the job carries no downloaded artifact to check (an image release, or a
// plain trigger job).
func artifactVerificationFor(params map[string]any) (artifactVerification, bool) {
	if params == nil {
		return artifactVerification{}, false
	}
	if _, ok := files.IsFileRef(params["artifact"]); !ok {
		return artifactVerification{}, false
	}
	v := artifactVerification{}
	v.checksum, _ = params["checksum_sha256"].(string)
	v.signature, _ = params["signature"].(string)
	v.serverKeyPEM, _ = params["artifact_public_key"].(string)
	v.applicationID, _ = params["application_id"].(string)
	return v, true
}

// artifactResult reports what verification actually established, so the job
// log can say whether a signature was checked and against which key, and the
// workflow can see which checks it no longer has to repeat.
type artifactResult struct {
	verifiedWith     string
	checksumVerified bool
	warnings         []string
}

func (r artifactResult) signatureVerified() bool { return r.verifiedWith != "" }

// envFlag renders a verification outcome for a step's environment.
func envFlag(ok bool) string {
	if ok {
		return "1"
	}
	return "0"
}

// verifyArtifact checks the downloaded artifact at path against the job's
// checksum and signature. A returned error means the workflow must not run.
func verifyArtifact(path string, v artifactVerification, p artifactPolicy) (artifactResult, error) {
	var res artifactResult
	if v.checksum != "" {
		if err := verifyArtifactChecksum(path, v.checksum); err != nil {
			return res, err
		}
		res.checksumVerified = true
	}
	if p.mode == verifyOff {
		res.warnings = append(res.warnings, "artifact signature check skipped (DEPLITE_ARTIFACT_VERIFY=off)")
		return res, nil
	}

	keyPEM, keyPath, err := readLocalArtifactKey(p.keyDir, v.applicationID)
	if err != nil {
		return res, err
	}
	source := "local key " + keyPath

	switch {
	case keyPEM != "" && v.serverKeyPEM != "":
		// A rotation legitimately leaves the two out of step for a while, and
		// the local key wins either way, so this is worth saying but not
		// worth failing over.
		if same, err := sameKey(keyPEM, v.serverKeyPEM); err == nil && !same {
			res.warnings = append(res.warnings, "the public key sent by the server differs from "+keyPath+"; verifying with the local key")
		}
	case keyPEM == "" && p.trustServer && v.serverKeyPEM != "":
		keyPEM = v.serverKeyPEM
		source = "server-supplied key (DEPLITE_ARTIFACT_TRUST_SERVER_KEY=1)"
		res.warnings = append(res.warnings, "no local public key; verifying with the key the server sent, which a compromised server could replace along with the signature")
	}

	defaultKeyPath := filepath.Join(p.keyDir, fallbackKeyName)
	if keyPEM == "" {
		switch {
		case p.mode == verifyRequire:
			return res, fmt.Errorf("artifact verification required but no trusted public key was found: install the signing public key at %s", defaultKeyPath)
		case v.signature != "":
			return res, fmt.Errorf("the release is signed but this device has no trusted public key: install the signing public key at %s, or set DEPLITE_ARTIFACT_TRUST_SERVER_KEY=1 to accept the one the server sends", defaultKeyPath)
		}
		res.warnings = append(res.warnings, "artifact is unverified: the release carries no signature and there is no public key at "+defaultKeyPath)
		return res, nil
	}
	if v.signature == "" {
		return res, errors.New("artifact verification is enabled by " + source + " but the release carries no signature")
	}
	if err := signing.VerifyBlobPEM(keyPEM, v.signature, path); err != nil {
		return res, err
	}
	res.verifiedWith = source
	return res, nil
}

// readLocalArtifactKey loads the public key this device trusts for an app,
// preferring a per-app file over the single-app default.
func readLocalArtifactKey(dir, applicationID string) (string, string, error) {
	names := make([]string, 0, 2)
	if applicationID != "" {
		names = append(names, filepath.Base(applicationID)+".pub")
	}
	names = append(names, fallbackKeyName)

	for _, name := range names {
		p := filepath.Join(dir, name)
		body, err := os.ReadFile(p)
		switch {
		case err == nil:
			// A key file that exists but does not parse is a misconfiguration,
			// not an absent key: falling back would silently deploy unverified.
			if _, perr := signing.ParsePublicKeyPEM(string(body)); perr != nil {
				return "", "", fmt.Errorf("trusted key %s: %w", p, perr)
			}
			return string(body), p, nil
		case os.IsNotExist(err):
			continue
		default:
			return "", "", fmt.Errorf("read trusted key %s: %w", p, err)
		}
	}
	return "", "", nil
}

func sameKey(aPEM, bPEM string) (bool, error) {
	a, err := signing.PublicKeyID(aPEM)
	if err != nil {
		return false, err
	}
	b, err := signing.PublicKeyID(bPEM)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

// verifyArtifactChecksum streams the file at path and fails if its sha256
// does not match expectedHex (compared case-insensitively).
func verifyArtifactChecksum(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedHex) {
		return fmt.Errorf("artifact checksum mismatch: expected %s", expectedHex)
	}
	return nil
}
