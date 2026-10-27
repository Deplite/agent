package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/signing"
	"gopkg.in/yaml.v3"
)

var updateVectors = flag.Bool("update", false, "regenerate approval interoperability vectors")

const testAgentID = "123e4567-e89b-12d3-a456-426614174000"

type vectorFile struct {
	Version     int               `json:"version"`
	Warning     string            `json:"warning"`
	Now         int64             `json:"now"`
	AgentID     string            `json:"agentId"`
	Description map[string]string `json:"description"`
	Canonical   []canonicalVector `json:"canonical"`
	Keys        keyVectors        `json:"keys"`
	X509        x509Vectors       `json:"x509"`
	Signatures  []signatureVector `json:"signatures"`
	TOTP        []totpVector      `json:"totp"`
	Decisions   []decisionVector  `json:"decisions"`
}

type canonicalInput struct {
	AgentID  string          `json:"agentId"`
	Workflow string          `json:"workflow"`
	Params   json.RawMessage `json:"params"`
	Ref      *string         `json:"ref"`
	Nonce    string          `json:"nonce"`
	TS       int64           `json:"ts"`
}

type canonicalVector struct {
	Name      string         `json:"name"`
	Input     canonicalInput `json:"input"`
	Canonical string         `json:"canonical,omitempty"`
	Error     bool           `json:"error,omitempty"`
}

type keyVectors struct {
	HMAC       map[string]string        `json:"hmac"`
	Ed25519    map[string]keyPairVector `json:"ed25519"`
	ECDSAP256  map[string]keyPairVector `json:"ecdsaP256"`
	TOTPSecret string                   `json:"totpSecretBase32"`
}

type keyPairVector struct {
	PrivateKeyPEM string `json:"privateKeyPEM"`
	PublicKeyPEM  string `json:"publicKeyPEM"`
}

type x509Vectors struct {
	CAs    map[string]string     `json:"cas"`
	Leaves map[string]leafVector `json:"leaves"`
}

type leafVector struct {
	Alg           string   `json:"alg"`
	PrivateKeyPEM string   `json:"privateKeyPEM"`
	CertChain     []string `json:"certChain"`
}

type signatureVector struct {
	Name          string `json:"name"`
	Method        string `json:"method,omitempty"`
	Alg           string `json:"alg,omitempty"`
	KeyID         string `json:"keyId"`
	Canonical     string `json:"canonical"`
	Sig           string `json:"sig"`
	Deterministic bool   `json:"deterministic"`
	DERSig        string `json:"derSig,omitempty"`
}

type totpVector struct {
	Name      string `json:"name"`
	Secret    string `json:"secretBase32"`
	Timestamp int64  `json:"timestamp"`
	Code      string `json:"code"`
	Code8     string `json:"code8,omitempty"`
}

type decisionPolicy struct {
	TOTP            bool     `json:"totp"`
	HMACKeys        []string `json:"hmacKeys"`
	TrustedKeys     []string `json:"trustedKeys"`
	TrustedCAs      []string `json:"trustedCAs"`
	AllowedSubjects []string `json:"allowedSubjects"`
}

type decisionJob struct {
	AgentID  string          `json:"agentId"`
	Workflow string          `json:"workflow"`
	Params   json.RawMessage `json:"params"`
	Ref      string          `json:"ref"`
}

type decisionStep struct {
	Now      *int64          `json:"now,omitempty"`
	Approval json.RawMessage `json:"approval"`
	Expect   string          `json:"expect"`
}

type decisionVector struct {
	Name     string         `json:"name"`
	Policy   decisionPolicy `json:"policy"`
	Job      decisionJob    `json:"job"`
	Sequence []decisionStep `json:"sequence"`
}

func TestVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "approval-vectors.json")
	if *updateVectors {
		vectors, err := makeVectors()
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || vectors.Now != 1792000000 || vectors.AgentID != testAgentID {
		t.Fatalf("unexpected vector header: %+v", vectors)
	}
	if vectors.Warning == "" || len(vectors.Description) < 6 {
		t.Fatal("vector warning and section descriptions are required")
	}
	for _, vector := range vectors.Canonical {
		t.Run("canonical/"+vector.Name, func(t *testing.T) {
			ref := ""
			if vector.Input.Ref != nil {
				ref = *vector.Input.Ref
			}
			req := Request{AgentID: vector.Input.AgentID, Workflow: vector.Input.Workflow, ParamsRaw: vector.Input.Params, Ref: ref}
			got, _, err := canonicalRequest(req, vector.Input.Nonce, vector.Input.TS)
			if vector.Error {
				if err == nil {
					t.Fatal("expected canonicalization error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != vector.Canonical {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, vector.Canonical)
			}
		})
	}
	verifySignatureVectors(t, vectors)
	verifyTOTPVectors(t, vectors)
	for _, vector := range vectors.Decisions {
		t.Run("decision/"+vector.Name, func(t *testing.T) {
			policy := loadVectorPolicy(t, vectors, vector.Policy)
			current := time.Unix(vectors.Now, 0)
			verifier := NewVerifier(func() time.Time { return current })
			for i, step := range vector.Sequence {
				stepNow := vectors.Now
				if step.Now != nil {
					stepNow = *step.Now
				}
				current = time.Unix(stepNow, 0)
				req := Request{AgentID: vector.Job.AgentID, Workflow: vector.Job.Workflow, ParamsRaw: vector.Job.Params, Ref: vector.Job.Ref, Approval: step.Approval}
				err := verifier.Verify(policy, req)
				if step.Expect == "ok" {
					if err != nil {
						t.Fatalf("step %d: unexpected rejection: %v", i, err)
					}
					continue
				}
				var rejection *Rejection
				if !errors.As(err, &rejection) {
					t.Fatalf("step %d: expected rejection %q, got %v", i, step.Expect, err)
				}
				if rejection.Code != step.Expect {
					t.Fatalf("step %d: got %q, want %q", i, rejection.Code, step.Expect)
				}
			}
		})
	}
}

func TestLoadFailClosed(t *testing.T) {
	if _, err := Load(Config{}); err == nil {
		t.Fatal("empty policy accepted")
	}
	if _, err := Load(Config{HMACKeysFile: "relative.yml"}); err == nil {
		t.Fatal("relative policy path accepted")
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("MZXW6===\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Config{TOTPSecretFile: secret}); err == nil {
		t.Fatal("short TOTP secret accepted")
	}
	policy := &Policy{totpSecret: []byte("secret-value"), hmacKeys: map[string][]byte{"id": []byte("private-key-value")}}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		logged := fmt.Sprintf(format, policy)
		if strings.Contains(logged, "secret-value") || strings.Contains(logged, "private-key-value") {
			t.Fatalf("policy formatting leaked secret material: %s", logged)
		}
	}
}

func verifySignatureVectors(t *testing.T, vectors vectorFile) {
	t.Helper()
	for _, vector := range vectors.Signatures {
		t.Run("signature/"+vector.Name, func(t *testing.T) {
			sig, err := base64.RawURLEncoding.Strict().DecodeString(vector.Sig)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case vector.Method == "hmac":
				key, err := base64.StdEncoding.DecodeString(vectors.Keys.HMAC[vector.KeyID])
				if err != nil {
					t.Fatal(err)
				}
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write([]byte(vector.Canonical))
				if !hmac.Equal(sig, mac.Sum(nil)) {
					t.Fatal("HMAC vector does not verify")
				}
			case vector.Alg == "ed25519":
				pair, ok := vectors.Keys.Ed25519[vector.KeyID]
				if !ok {
					t.Fatalf("unknown Ed25519 key id %q", vector.KeyID)
				}
				private := parsePrivateKey(t, pair.PrivateKeyPEM).(ed25519.PrivateKey)
				if !ed25519.Verify(private.Public().(ed25519.PublicKey), []byte(vector.Canonical), sig) {
					t.Fatal("Ed25519 vector does not verify")
				}
				if vector.Deterministic && !bytes.Equal(sig, ed25519.Sign(private, []byte(vector.Canonical))) {
					t.Fatal("deterministic Ed25519 signature changed")
				}
			case vector.Alg == "ecdsa-p256-sha256":
				pair, ok := vectors.Keys.ECDSAP256[vector.KeyID]
				if !ok {
					t.Fatalf("unknown ECDSA key id %q", vector.KeyID)
				}
				private := parsePrivateKey(t, pair.PrivateKeyPEM).(*ecdsa.PrivateKey)
				if !verifySignature(vector.Alg, &private.PublicKey, []byte(vector.Canonical), sig) {
					t.Fatal("ECDSA vector does not verify")
				}
				if vector.Deterministic {
					t.Fatal("ECDSA vector must be marked nondeterministic")
				}
			default:
				t.Fatalf("unknown signature vector method/algorithm %q/%q", vector.Method, vector.Alg)
			}
			if vector.DERSig != "" {
				der, err := base64.RawURLEncoding.Strict().DecodeString(vector.DERSig)
				if err != nil {
					t.Fatal(err)
				}
				nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
				if _, _, err := decodeNonceAndSig(nonce, vector.DERSig, 64); err == nil {
					t.Fatal("DER ECDSA signature accepted as P1363")
				}
				var pair struct{ R, S *big.Int }
				if _, err := asn1.Unmarshal(der, &pair); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func verifyTOTPVectors(t *testing.T, vectors vectorFile) {
	t.Helper()
	for _, vector := range vectors.TOTP {
		t.Run("totp/"+vector.Name, func(t *testing.T) {
			secret, err := decodeTOTPSecret(vector.Secret)
			if err != nil {
				t.Fatal(err)
			}
			if vector.Code8 != "" {
				if got := hotp(secret, uint64(vector.Timestamp/30), 8); got != vector.Code8 {
					t.Fatalf("got %s, want %s", got, vector.Code8)
				}
				if vector.Code != vector.Code8[len(vector.Code8)-6:] {
					t.Fatal("6-digit code is not the RFC vector suffix")
				}
			} else if got := hotp(secret, uint64(vector.Timestamp/30), 6); got != vector.Code {
				t.Fatalf("got %s, want %s", got, vector.Code)
			}
		})
	}
}

func loadVectorPolicy(t *testing.T, vectors vectorFile, spec decisionPolicy) *Policy {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{AllowedSubjects: spec.AllowedSubjects}
	if spec.TOTP {
		cfg.TOTPSecretFile = filepath.Join(dir, "totp.txt")
		if err := os.WriteFile(cfg.TOTPSecretFile, []byte(vectors.Keys.TOTPSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(spec.HMACKeys) > 0 {
		values := make(map[string]string)
		for _, id := range spec.HMACKeys {
			values[id] = vectors.Keys.HMAC[id]
		}
		cfg.HMACKeysFile = filepath.Join(dir, "hmac.yml")
		writeYAMLFile(t, cfg.HMACKeysFile, values)
	}
	if len(spec.TrustedKeys) > 0 {
		values := make(map[string]string)
		for _, id := range spec.TrustedKeys {
			var publicPEM string
			for _, keySet := range []map[string]keyPairVector{vectors.Keys.Ed25519, vectors.Keys.ECDSAP256} {
				if pair, ok := keySet[id]; ok {
					publicPEM = pair.PublicKeyPEM
					break
				}
			}
			if publicPEM == "" {
				t.Fatalf("unknown public key reference %q", id)
			}
			values[id] = publicPEM
		}
		cfg.TrustedKeysFile = filepath.Join(dir, "trusted.yml")
		writeYAMLFile(t, cfg.TrustedKeysFile, values)
	}
	if len(spec.TrustedCAs) > 0 {
		var contents strings.Builder
		for _, name := range spec.TrustedCAs {
			pemText, ok := vectors.X509.CAs[name]
			if !ok {
				t.Fatalf("unknown CA reference %q", name)
			}
			contents.WriteString(pemText)
		}
		cfg.TrustedCAFile = filepath.Join(dir, "roots.pem")
		if err := os.WriteFile(cfg.TrustedCAFile, []byte(contents.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func writeYAMLFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := yamlMarshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func yamlMarshal(value any) ([]byte, error) { return yaml.Marshal(value) }

func parsePrivateKey(t *testing.T, text string) any {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("missing private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func makeVectors() (vectorFile, error) {
	now := int64(1792000000)
	hmacKey := []byte("0123456789abcdef0123456789abcdef")
	edSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	edPrivate := ed25519.NewKeyFromSeed(edSeed)
	ecPrivate := ecdsaPrivate(1)
	secret := []byte("this is a test totp secret")
	secretBase32 := encodeBase32NoPad(secret)
	rootKey := ecdsaPrivate(2)
	intermediateKey := ecdsaPrivate(3)
	otherRootKey := ecdsaPrivate(4)
	rootPEM, rootDER, err := makeCertificate(now, "Approval Test Root", rootKey, rootKey, nil, true, true, now-3650*86400, now+5000*86400)
	if err != nil {
		return vectorFile{}, err
	}
	intermediatePEM, intermediateDER, err := makeCertificate(now, "Approval Test Intermediate", intermediateKey, rootKey, rootDER, true, false, now-3650*86400, now+5000*86400)
	if err != nil {
		return vectorFile{}, err
	}
	otherCAPEM, otherDER, err := makeCertificate(now, "Untrusted Approval Root", otherRootKey, otherRootKey, nil, true, true, now-3650*86400, now+5000*86400)
	if err != nil {
		return vectorFile{}, err
	}
	leafDefs := map[string]struct {
		key                 any
		signer              any
		parent              []byte
		cn, alg             string
		dns                 []string
		keyUsage            x509.KeyUsage
		notBefore, notAfter int64
	}{
		"ops-alice":            {key: ecdsaPrivate(5), signer: intermediateKey, parent: intermediateDER, cn: "ops-alice", alg: "ecdsa-p256-sha256", keyUsage: x509.KeyUsageDigitalSignature, notBefore: now - 30*86400, notAfter: now + 3650*86400},
		"ops-bob":              {key: edPrivate, signer: rootKey, parent: rootDER, cn: "ops-bob", alg: "ed25519", dns: []string{"approvers.example"}, keyUsage: x509.KeyUsageDigitalSignature, notBefore: now - 30*86400, notAfter: now + 3650*86400},
		"expired":              {key: ecdsaPrivate(6), signer: rootKey, parent: rootDER, cn: "expired-user", alg: "ecdsa-p256-sha256", keyUsage: x509.KeyUsageDigitalSignature, notBefore: now - 365*86400, notAfter: now - 86400},
		"no-digital-signature": {key: ecdsaPrivate(7), signer: rootKey, parent: rootDER, cn: "no-sign-user", alg: "ecdsa-p256-sha256", keyUsage: x509.KeyUsageKeyEncipherment, notBefore: now - 30*86400, notAfter: now + 3650*86400},
		"other-ca":             {key: ecdsaPrivate(8), signer: otherRootKey, parent: otherDER, cn: "other-ca-user", alg: "ecdsa-p256-sha256", keyUsage: x509.KeyUsageDigitalSignature, notBefore: now - 30*86400, notAfter: now + 3650*86400},
		"dev-carol":            {key: ecdsaPrivate(9), signer: intermediateKey, parent: intermediateDER, cn: "dev-carol", alg: "ecdsa-p256-sha256", keyUsage: x509.KeyUsageDigitalSignature, notBefore: now - 30*86400, notAfter: now + 3650*86400},
	}
	leaves := make(map[string]leafVector)
	for name, spec := range leafDefs {
		options := []any{spec.keyUsage}
		for _, dns := range spec.dns {
			options = append(options, dns)
		}
		pemCert, der, err := makeCertificate(now, spec.cn, spec.key, spec.signer, spec.parent, false, false, spec.notBefore, spec.notAfter, options...)
		if err != nil {
			return vectorFile{}, err
		}
		_ = pemCert
		chain := []string{base64.StdEncoding.EncodeToString(der)}
		if len(spec.parent) > 0 && !bytes.Equal(spec.parent, rootDER) && !bytes.Equal(spec.parent, otherDER) {
			chain = append(chain, base64.StdEncoding.EncodeToString(spec.parent))
		}
		leaves[name] = leafVector{Alg: spec.alg, PrivateKeyPEM: privatePEM(spec.key), CertChain: chain}
	}
	keys := keyVectors{
		HMAC:       map[string]string{"test-hmac": base64.StdEncoding.EncodeToString(hmacKey)},
		Ed25519:    map[string]keyPairVector{"signer-ed": {PrivateKeyPEM: privatePEM(edPrivate), PublicKeyPEM: publicPEM(edPrivate.Public())}},
		ECDSAP256:  map[string]keyPairVector{"signer-ec": {PrivateKeyPEM: privatePEM(ecPrivate), PublicKeyPEM: publicPEM(&ecPrivate.PublicKey)}},
		TOTPSecret: secretBase32,
	}
	canonicalCase := func(name, params, ref string) canonicalVector {
		var refValue *string
		if ref != "" {
			refValue = &ref
		}
		input := canonicalInput{AgentID: testAgentID, Workflow: "deploy", Params: json.RawMessage(params), Ref: refValue, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16)), TS: now}
		inputRef := ""
		if input.Ref != nil {
			inputRef = *input.Ref
		}
		bytes, _, err := canonicalRequest(Request{AgentID: input.AgentID, Workflow: input.Workflow, ParamsRaw: input.Params, Ref: inputRef}, input.Nonce, input.TS)
		if err != nil {
			return canonicalVector{Name: name, Input: input, Error: true}
		}
		return canonicalVector{Name: name, Input: input, Canonical: string(bytes)}
	}
	canonical := []canonicalVector{
		canonicalCase("empty-params-ref-null", `{}`, ""),
		canonicalCase("string-integers-bool", `{"z":"text","p":-7,"b":true,"n":0}`, "main"),
		canonicalCase("unicode-and-escapes", `{"s":"<>&\u2028\u2029\n\t\b\f\r\"\\ 한글 😀"}`, "release/한글"),
		canonicalCase("sorted-keys", `{"z":1,"a":{"z":2,"a":3},"m":[{"b":1,"a":0}]}`, ""),
		canonicalCase("integral-number-normalization", `{"f":1.0,"e":1e2,"negativeZero":-0,"negative":-3}`, ""),
		canonicalCase("system-fields-removed", `{"DEPLITE_JOB_ID":"server","DEPLITE_BAD":1.5,"registry_token":9007199254740992,"ok":1,"nested":{"DEPLITE_KEEP":2}}`, ""),
		canonicalCase("fraction-error", `{"value":1.5}`, ""),
		canonicalCase("unsafe-integer-error", `{"value":9007199254740992}`, ""),
		canonicalCase("unsafe-exponent-error", `{"value":1e40}`, ""),
		canonicalCase("non-ascii-object-key-error", `{"meta":{"é":"x"}}`, ""),
	}
	canonicalForSig := canonicalCase("signature-message", `{"a":1,"message":"approval vectors"}`, "refs/main")
	msg := []byte(canonicalForSig.Canonical)
	hmacSum := hmac.New(sha256.New, hmacKey)
	_, _ = hmacSum.Write(msg)
	edSig := ed25519.Sign(edPrivate, msg)
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, ecPrivate, digest[:])
	if err != nil {
		return vectorFile{}, err
	}
	p1363 := make([]byte, 64)
	r.FillBytes(p1363[:32])
	s.FillBytes(p1363[32:])
	derSig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return vectorFile{}, err
	}
	signatures := []signatureVector{
		{Name: "hmac-sha256", Method: "hmac", KeyID: "test-hmac", Canonical: string(msg), Sig: base64.RawURLEncoding.EncodeToString(hmacSum.Sum(nil)), Deterministic: true},
		{Name: "ed25519", Alg: "ed25519", KeyID: "signer-ed", Canonical: string(msg), Sig: base64.RawURLEncoding.EncodeToString(edSig), Deterministic: true},
		{Name: "ecdsa-p256-p1363", Alg: "ecdsa-p256-sha256", KeyID: "signer-ec", Canonical: string(msg), Sig: base64.RawURLEncoding.EncodeToString(p1363), Deterministic: false, DERSig: base64.RawURLEncoding.EncodeToString(derSig)},
	}
	totpVectors := make([]totpVector, 0, 7)
	rfcSecret := []byte("12345678901234567890")
	rfcBase32 := encodeBase32NoPad(rfcSecret)
	for _, item := range []struct {
		ts    int64
		value string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		totpVectors = append(totpVectors, totpVector{Name: fmt.Sprintf("rfc6238-%d", item.ts), Secret: rfcBase32, Timestamp: item.ts, Code: item.value[len(item.value)-6:], Code8: item.value})
	}
	totpVectors = append(totpVectors, totpVector{Name: "node-now", Secret: secretBase32, Timestamp: now, Code: hotp(secret, uint64(now/30), 6)})

	baseJob := decisionJob{AgentID: testAgentID, Workflow: "deploy", Params: json.RawMessage(`{"release":"v1"}`), Ref: "refs/main"}
	jobRequest := func(job decisionJob) Request {
		return Request{AgentID: job.AgentID, Workflow: job.Workflow, ParamsRaw: job.Params, Ref: job.Ref}
	}
	nonceCounter := byte(1)
	nextNonce := func() string {
		b := bytes.Repeat([]byte{nonceCounter}, 16)
		nonceCounter++
		return base64.RawURLEncoding.EncodeToString(b)
	}
	makeHMACForCanonical := func(canonical []byte, ts int64, keyID, nonce string, key []byte) json.RawMessage {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(canonical)
		return rawJSON(map[string]any{"method": "hmac", "keyId": keyID, "nonce": nonce, "ts": ts, "sig": base64.RawURLEncoding.EncodeToString(mac.Sum(nil))})
	}
	makeHMAC := func(job decisionJob, ts int64, keyID, nonce string, key []byte) json.RawMessage {
		canonical, _, err := canonicalRequest(jobRequest(job), nonce, ts)
		if err != nil {
			panic(err)
		}
		return makeHMACForCanonical(canonical, ts, keyID, nonce, key)
	}
	makeSignature := func(job decisionJob, ts int64, nonce, alg, keyID string, chain []string, private any) json.RawMessage {
		canonical, _, err := canonicalRequest(jobRequest(job), nonce, ts)
		if err != nil {
			panic(err)
		}
		var sig []byte
		switch key := private.(type) {
		case ed25519.PrivateKey:
			sig = ed25519.Sign(key, canonical)
		case *ecdsa.PrivateKey:
			digest := sha256.Sum256(canonical)
			rr, ss, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				panic(err)
			}
			sig = make([]byte, 64)
			rr.FillBytes(sig[:32])
			ss.FillBytes(sig[32:])
		default:
			panic("unsupported test private key")
		}
		wire := map[string]any{"method": "signature", "alg": alg, "nonce": nonce, "ts": ts, "sig": base64.RawURLEncoding.EncodeToString(sig)}
		if keyID != "" {
			wire["keyId"] = keyID
		} else {
			wire["certChain"] = chain
		}
		return rawJSON(wire)
	}
	makeDERApproval := func(job decisionJob, nonce string) json.RawMessage {
		canonical, _, err := canonicalRequest(jobRequest(job), nonce, now)
		if err != nil {
			panic(err)
		}
		digest := sha256.Sum256(canonical)
		rr, ss, err := ecdsa.Sign(rand.Reader, ecPrivate, digest[:])
		if err != nil {
			panic(err)
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{rr, ss})
		if err != nil {
			panic(err)
		}
		return rawJSON(map[string]any{"method": "signature", "alg": "ecdsa-p256-sha256", "keyId": "signer-ec", "nonce": nonce, "ts": now, "sig": base64.RawURLEncoding.EncodeToString(der)})
	}
	step := func(ts int64, approval json.RawMessage, expect string) decisionStep {
		return decisionStep{Now: &ts, Approval: approval, Expect: expect}
	}
	policyHMAC := decisionPolicy{HMACKeys: []string{"test-hmac"}}
	policyTOTP := decisionPolicy{TOTP: true}
	policyCA := decisionPolicy{TrustedCAs: []string{"rootCA"}}
	decisions := []decisionVector{}
	add := func(name string, policy decisionPolicy, job decisionJob, sequence ...decisionStep) {
		if policy.HMACKeys == nil {
			policy.HMACKeys = []string{}
		}
		if policy.TrustedKeys == nil {
			policy.TrustedKeys = []string{}
		}
		if policy.TrustedCAs == nil {
			policy.TrustedCAs = []string{}
		}
		if policy.AllowedSubjects == nil {
			policy.AllowedSubjects = []string{}
		}
		decisions = append(decisions, decisionVector{Name: name, Policy: policy, Job: job, Sequence: sequence})
	}
	totpCode := hotp(secret, uint64(now/30), 6)
	wrongCode := "000000"
	if wrongCode == totpCode {
		wrongCode = "000001"
	}
	add("totp-ok", policyTOTP, baseJob, step(now, rawJSON(map[string]any{"method": "totp", "code": totpCode}), "ok"))
	add("totp-wrong-code", policyTOTP, baseJob, step(now, rawJSON(map[string]any{"method": "totp", "code": wrongCode}), CodeInvalid))
	add("totp-step-replay", policyTOTP, baseJob,
		step(now, rawJSON(map[string]any{"method": "totp", "code": totpCode}), "ok"),
		step(now, rawJSON(map[string]any{"method": "totp", "code": totpCode}), CodeReplayed))
	throttle := make([]decisionStep, 0, 6)
	for i := 0; i < 5; i++ {
		throttle = append(throttle, step(now, rawJSON(map[string]any{"method": "totp", "code": wrongCode}), CodeInvalid))
	}
	throttle = append(throttle, step(now, rawJSON(map[string]any{"method": "totp", "code": totpCode}), CodeInvalid))
	add("totp-workflow-throttle", policyTOTP, baseJob, throttle...)
	add("method-not-allowed", policyHMAC, baseJob, step(now, rawJSON(map[string]any{"method": "totp", "code": totpCode}), CodeMethodNotAllowed))

	nonce := nextNonce()
	add("hmac-ok", policyHMAC, baseJob, step(now, makeHMAC(baseJob, now, "test-hmac", nonce, hmacKey), "ok"))
	goodBadSig := makeHMAC(baseJob, now, "test-hmac", nextNonce(), hmacKey)
	var badMap map[string]any
	_ = json.Unmarshal(goodBadSig, &badMap)
	decodedSig, _ := base64.RawURLEncoding.DecodeString(badMap["sig"].(string))
	decodedSig[0] ^= 1
	badMap["sig"] = base64.RawURLEncoding.EncodeToString(decodedSig)
	add("hmac-bad-signature", policyHMAC, baseJob, step(now, rawJSON(badMap), CodeInvalid))
	unknownID := makeHMAC(baseJob, now, "missing", nextNonce(), hmacKey)
	add("hmac-unregistered-key", policyHMAC, baseJob, step(now, unknownID, CodeInvalid))
	oldTS := now - 301
	add("hmac-expired", policyHMAC, baseJob, step(now, makeHMAC(baseJob, oldTS, "test-hmac", nextNonce(), hmacKey), CodeExpired))
	futureTS := now + 299
	add("hmac-future-within-window", policyHMAC, baseJob, step(now, makeHMAC(baseJob, futureTS, "test-hmac", nextNonce(), hmacKey), "ok"))
	replayWire := makeHMAC(baseJob, now, "test-hmac", nextNonce(), hmacKey)
	add("hmac-nonce-replay", policyHMAC, baseJob, step(now, replayWire, "ok"), step(now, replayWire, CodeReplayed))
	shortNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 15))
	add("hmac-short-nonce", policyHMAC, baseJob, step(now, makeHMAC(baseJob, now, "test-hmac", shortNonce, hmacKey), CodeInvalid))

	add("ed25519-key-id", decisionPolicy{TrustedKeys: []string{"signer-ed"}}, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ed25519", "signer-ed", nil, edPrivate), "ok"))
	add("ecdsa-key-id", decisionPolicy{TrustedKeys: []string{"signer-ec"}}, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "signer-ec", nil, ecPrivate), "ok"))
	add("ecdsa-DER-signature-rejected", decisionPolicy{TrustedKeys: []string{"signer-ec"}}, baseJob, step(now, makeDERApproval(baseJob, nextNonce()), CodeInvalid))
	add("algorithm-key-mismatch", decisionPolicy{TrustedKeys: []string{"signer-ed"}}, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "signer-ed", nil, edPrivate), CodeInvalid))
	add("x509-ecdsa-intermediate", policyCA, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "", leaves["ops-alice"].CertChain, leafDefs["ops-alice"].key), "ok"))
	add("x509-ed25519", policyCA, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ed25519", "", leaves["ops-bob"].CertChain, edPrivate), "ok"))
	add("x509-expired", policyCA, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "", leaves["expired"].CertChain, leafDefs["expired"].key), CodeUntrustedCert))
	add("x509-other-CA", policyCA, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "", leaves["other-ca"].CertChain, leafDefs["other-ca"].key), CodeUntrustedCert))
	add("x509-subject-denied", decisionPolicy{TrustedCAs: []string{"rootCA"}, AllowedSubjects: []string{"dev-*"}}, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ed25519", "", leaves["ops-bob"].CertChain, edPrivate), CodeUntrustedCert))
	add("x509-DNS-SAN-allowed", decisionPolicy{TrustedCAs: []string{"rootCA"}, AllowedSubjects: []string{"approvers.*"}}, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ed25519", "", leaves["ops-bob"].CertChain, edPrivate), "ok"))
	add("x509-no-digital-signature", policyCA, baseJob, step(now, makeSignature(baseJob, now, nextNonce(), "ecdsa-p256-sha256", "", leaves["no-digital-signature"].CertChain, leafDefs["no-digital-signature"].key), CodeUntrustedCert))

	baseApproval := makeHMAC(baseJob, now, "test-hmac", nextNonce(), hmacKey)
	mutParams := baseJob
	mutParams.Params = json.RawMessage(`{"release":"v2"}`)
	add("tampered-params", policyHMAC, mutParams, step(now, baseApproval, CodeInvalid))
	mutRef := baseJob
	mutRef.Ref = "refs/other"
	add("tampered-ref", policyHMAC, mutRef, step(now, baseApproval, CodeInvalid))
	mutWorkflow := baseJob
	mutWorkflow.Workflow = "other"
	add("tampered-workflow", policyHMAC, mutWorkflow, step(now, baseApproval, CodeInvalid))
	mutAgent := baseJob
	mutAgent.AgentID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	add("tampered-agent", policyHMAC, mutAgent, step(now, baseApproval, CodeInvalid))
	add("approval-required", policyHMAC, baseJob, step(now, json.RawMessage("null"), CodeRequired))
	badParams := baseJob
	badParams.Params = json.RawMessage(`{"value":1.5}`)
	add("fractional-job-params", policyHMAC, badParams, step(now, baseApproval, CodeInvalid))
	systemParams := baseJob
	systemParams.Params = json.RawMessage(`{"release":"v1","DEPLITE_JOB_ID":"server","registry_token":"server-owned"}`)
	systemApproval := makeHMAC(baseJob, now, "test-hmac", nextNonce(), hmacKey)
	add("server-owned-params-removed", policyHMAC, systemParams, step(now, systemApproval, "ok"))
	nonASCIIKeyJob := baseJob
	nonASCIIKeyJob.Params = json.RawMessage(`{"meta":{"é":"x"}}`)
	nonASCIIParams, err := decodeJSON(nonASCIIKeyJob.Params)
	if err != nil {
		return vectorFile{}, err
	}
	nonASCIIKeyNonce := nextNonce()
	nonASCIIRef := any(nonASCIIKeyJob.Ref)
	if nonASCIIKeyJob.Ref == "" {
		nonASCIIRef = nil
	}
	nonASCIICanonical, err := signing.CanonicalJSON(map[string]any{
		"agentId":  nonASCIIKeyJob.AgentID,
		"nonce":    nonASCIIKeyNonce,
		"params":   nonASCIIParams,
		"ref":      nonASCIIRef,
		"ts":       json.Number(fmt.Sprint(now)),
		"v":        json.Number("1"),
		"workflow": nonASCIIKeyJob.Workflow,
	})
	if err != nil {
		return vectorFile{}, err
	}
	nonASCIIApproval := makeHMACForCanonical(nonASCIICanonical, now, "test-hmac", nonASCIIKeyNonce, hmacKey)
	add("non-ascii-object-key-hmac", policyHMAC, nonASCIIKeyJob, step(now, nonASCIIApproval, CodeInvalid))

	return vectorFile{Version: 1, Warning: "Test-only private keys and certificates. Never use this material for real approvals.", Now: now, AgentID: testAgentID,
		Description: map[string]string{
			"canonical":  "Canonical request bytes; params object keys must be ASCII. error:true means params normalization failed. Raw numeric literals are preserved in input.params.",
			"keys":       "Test-only key material is indexed by keyId; hmac, ed25519, and ecdsaP256 are direct keyId maps.",
			"x509":       "CA PEM values are named in cas; leaf certChain is standard-base64 DER, leaf first.",
			"signatures": "ECDSA deterministic:false is verification-only; derSig is DER and must be rejected in favor of P1363.",
			"totp":       "code8 preserves the original RFC 8-digit result; code is its six-digit suffix.",
			"decisions":  "Each case gets a fresh Verifier; sequence shares that state in order. job.params is raw input JSON. Time uses step.now, or top-level now when absent.",
		},
		Canonical: canonical, Keys: keys, X509: x509Vectors{CAs: map[string]string{"rootCA": rootPEM, "intermediateCA": intermediatePEM, "otherCA": otherCAPEM}, Leaves: leaves}, Signatures: signatures, TOTP: totpVectors, Decisions: decisions}, nil
}

func rawJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func ecdsaPrivate(scalar int64) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	d := big.NewInt(scalar)
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
}

func privateDER(private any) []byte {
	data, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		panic(err)
	}
	return data
}

func privatePEM(private any) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER(private)}))
}

func publicPEM(public any) string {
	data, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}))
}

func makeCertificate(now int64, commonName string, subjectKey, signer any, parentDER []byte, isCA, self bool, notBefore, notAfter int64, usages ...any) (string, []byte, error) {
	var keyUsage x509.KeyUsage
	var dns []string
	for _, option := range usages {
		switch value := option.(type) {
		case x509.KeyUsage:
			keyUsage = value
		case string:
			dns = append(dns, value)
		}
	}
	if isCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	serialBytes := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s", commonName, now, fmt.Sprint(notAfter))))
	serial := new(big.Int).SetBytes(serialBytes[:16])
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Unix(notBefore, 0).UTC(), NotAfter: time.Unix(notAfter, 0).UTC(), KeyUsage: keyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true, IsCA: isCA, DNSNames: dns}
	if isCA {
		template.MaxPathLen = 1
		template.MaxPathLenZero = false
	}
	parent := template
	parentKey := signer
	if !self {
		block, _ := pem.Decode(parentDERToPEM(parentDER))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", nil, err
		}
		parent = cert
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey(subjectKey), parentKey)
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der, nil
}

func parentDERToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func publicKey(private any) any {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey)
	default:
		panic("unsupported key")
	}
}

func encodeBase32NoPad(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var output strings.Builder
	var buffer uint32
	bits := uint(0)
	for _, b := range data {
		buffer = buffer<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			output.WriteByte(alphabet[(buffer>>bits)&31])
			buffer &= (1 << bits) - 1
		}
	}
	if bits > 0 {
		output.WriteByte(alphabet[(buffer<<(5-bits))&31])
	}
	return output.String()
}
