// Package approval validates workflow execution approvals using node-held trust material.
package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Deplite/agent/internal/signing"
	"gopkg.in/yaml.v3"
)

const (
	CodeRequired          = "approval_required"
	CodeMethodNotAllowed  = "approval_method_not_allowed"
	CodeInvalid           = "approval_invalid"
	CodeExpired           = "approval_expired"
	CodeReplayed          = "approval_replayed"
	CodeUntrustedCert     = "approval_untrusted_cert"
	CodeAgentMismatch     = "approval_agent_mismatch"
	canonicalMaxInteger   = int64(1<<53 - 1)
	approvalTimeTolerance = int64(300)
)

// Config describes the files that define a node's local approval policy.
type Config struct {
	TOTPSecretFile  string
	HMACKeysFile    string
	TrustedKeysFile string
	TrustedCAFile   string
	AllowedSubjects []string
}

// Policy contains parsed approval methods and their node-local trust material.
type Policy struct {
	totpSecret      []byte
	hmacKeys        map[string][]byte
	trustedKeys     map[string]any
	roots           *x509.CertPool
	methods         []string
	allowedSubjects []string
}

// Load reads and validates policy files. Every configured path must be absolute.
func Load(cfg Config) (*Policy, error) {
	p := &Policy{hmacKeys: make(map[string][]byte), trustedKeys: make(map[string]any), allowedSubjects: append([]string(nil), cfg.AllowedSubjects...)}
	for _, path := range []string{cfg.TOTPSecretFile, cfg.HMACKeysFile, cfg.TrustedKeysFile, cfg.TrustedCAFile} {
		if path != "" && !filepath.IsAbs(path) {
			return nil, fmt.Errorf("approval: configured file path must be absolute")
		}
	}
	if cfg.TOTPSecretFile != "" {
		b, err := os.ReadFile(cfg.TOTPSecretFile)
		if err != nil {
			return nil, fmt.Errorf("approval: read TOTP secret: %w", err)
		}
		p.totpSecret, err = decodeTOTPSecret(string(b))
		if err != nil {
			return nil, fmt.Errorf("approval: invalid TOTP secret: %w", err)
		}
		p.methods = append(p.methods, "totp")
	}
	if cfg.HMACKeysFile != "" {
		values, err := readYAMLStringMap(cfg.HMACKeysFile)
		if err != nil {
			return nil, fmt.Errorf("approval: read HMAC keys: %w", err)
		}
		for id, encoded := range values {
			if !validKeyID(id) {
				return nil, fmt.Errorf("approval: invalid HMAC key id")
			}
			key, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(key) < 32 {
				return nil, fmt.Errorf("approval: HMAC keys must be standard base64 and at least 32 bytes")
			}
			p.hmacKeys[id] = key
		}
		if len(p.hmacKeys) == 0 {
			return nil, fmt.Errorf("approval: HMAC key file is empty")
		}
		p.methods = append(p.methods, "hmac")
	}
	if cfg.TrustedKeysFile != "" {
		values, err := readYAMLStringMap(cfg.TrustedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("approval: read trusted keys: %w", err)
		}
		for id, encoded := range values {
			if !validKeyID(id) {
				return nil, fmt.Errorf("approval: invalid trusted key id")
			}
			trimmed := bytes.TrimSpace([]byte(encoded))
			block, rest := pem.Decode(trimmed)
			if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
				return nil, fmt.Errorf("approval: trusted key must be PKIX PUBLIC KEY PEM")
			}
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil || !supportedPublicKey(key) {
				return nil, fmt.Errorf("approval: unsupported trusted public key")
			}
			p.trustedKeys[id] = key
		}
		if len(p.trustedKeys) == 0 {
			return nil, fmt.Errorf("approval: trusted key file is empty")
		}
	}
	if cfg.TrustedCAFile != "" {
		b, err := os.ReadFile(cfg.TrustedCAFile)
		if err != nil {
			return nil, fmt.Errorf("approval: read trusted CAs: %w", err)
		}
		p.roots = x509.NewCertPool()
		count := 0
		for len(bytes.TrimSpace(b)) > 0 {
			b = bytes.TrimSpace(b)
			block, rest := pem.Decode(b)
			if block == nil || block.Type != "CERTIFICATE" || !bytes.HasPrefix(b, []byte("-----BEGIN ")) {
				return nil, fmt.Errorf("approval: CA file must contain PEM certificates")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("approval: invalid CA certificate: %w", err)
			}
			p.roots.AddCert(cert)
			count++
			b = rest
		}
		if count == 0 {
			return nil, fmt.Errorf("approval: CA file is empty")
		}
	}
	if len(cfg.AllowedSubjects) > 0 && cfg.TrustedCAFile == "" {
		return nil, fmt.Errorf("approval: allowed subjects require a trusted CA file")
	}
	if cfg.TrustedKeysFile != "" || cfg.TrustedCAFile != "" {
		p.methods = append(p.methods, "signature")
	}
	if len(p.methods) == 0 {
		return nil, fmt.Errorf("approval: at least one method must be configured")
	}
	sort.Strings(p.methods)
	return p, nil
}

// Methods returns the sorted approval methods enabled by the policy.
func (p *Policy) Methods() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.methods...)
}

// String returns a redacted policy summary.
func (p *Policy) String() string {
	if p == nil {
		return "approval.Policy<nil>"
	}
	return fmt.Sprintf("approval.Policy{methods:%v}", p.methods)
}

// GoString keeps formatted policy values redacted as well.
func (p *Policy) GoString() string { return p.String() }

// Request contains the job identity, raw params, and the job's approval JSON.
type Request struct {
	AgentID   string
	Workflow  string
	ParamsRaw json.RawMessage
	Ref       string
	Approval  json.RawMessage
}

// Rejection is a stable approval failure safe to return to callers.
type Rejection struct {
	Code    string
	Message string
}

func (r *Rejection) Error() string { return r.Message }

// Verifier holds replay and TOTP throttling state shared by concurrent calls.
type Verifier struct {
	mu       sync.Mutex
	now      func() time.Time
	replayed map[string]int64
	totpUsed map[string]int64
	failures map[string][]int64
}

// NewVerifier creates a verifier using now for clock reads; nil uses the system clock.
func NewVerifier(now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{now: now, replayed: make(map[string]int64), totpUsed: make(map[string]int64), failures: make(map[string][]int64)}
}

// Verify checks an approval; call NormalizeParams to retrieve the sanitized job params.
func (v *Verifier) Verify(policy *Policy, req Request) error {
	if v == nil {
		v = NewVerifier(nil)
	}
	v.initialize()
	if policy == nil {
		return reject(CodeInvalid, "approval policy is unavailable")
	}
	if len(bytes.TrimSpace(req.Approval)) == 0 || bytes.Equal(bytes.TrimSpace(req.Approval), []byte("null")) {
		return reject(CodeRequired, "approval is required")
	}
	var methodProbe struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(req.Approval, &methodProbe); err != nil || methodProbe.Method == "" {
		return reject(CodeInvalid, "approval is malformed")
	}
	if !contains(policy.methods, methodProbe.Method) {
		return reject(CodeMethodNotAllowed, "approval method is not allowed")
	}
	switch methodProbe.Method {
	case "totp":
		return v.verifyTOTP(policy, req)
	case "hmac":
		return v.verifyHMAC(policy, req)
	case "signature":
		return v.verifySignature(policy, req)
	default:
		return reject(CodeInvalid, "approval method is malformed")
	}
}

func (v *Verifier) initialize() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.now == nil {
		v.now = time.Now
	}
	if v.replayed == nil {
		v.replayed = make(map[string]int64)
	}
	if v.totpUsed == nil {
		v.totpUsed = make(map[string]int64)
	}
	if v.failures == nil {
		v.failures = make(map[string][]int64)
	}
}

// NormalizeParams removes server-owned fields and returns canonical JSON with ASCII keys and safe integers only.
func NormalizeParams(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	value, err := decodeJSONRaw(raw)
	if err != nil {
		return nil, err
	}
	params, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("params must be an object")
	}
	for key := range params {
		if strings.HasPrefix(key, "DEPLITE_") || key == "registry_token" {
			delete(params, key)
		}
	}
	if err := validateASCIIObjectKeys(params); err != nil {
		return nil, err
	}
	paramsValue, err := normalizeNumbers(params)
	if err != nil {
		return nil, err
	}
	canonical, err := signing.CanonicalJSON(paramsValue)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func validateASCIIObjectKeys(value any) error {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			for i := 0; i < len(key); i++ {
				if key[i] > 0x7f {
					return errors.New("params object keys must be ASCII")
				}
			}
			if err := validateASCIIObjectKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := validateASCIIObjectKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *Verifier) verifyTOTP(p *Policy, req Request) error {
	now := v.now().Unix()
	v.mu.Lock()
	v.pruneLocked(now)
	if len(v.failures[req.Workflow]) >= 5 {
		v.mu.Unlock()
		return reject(CodeInvalid, "TOTP attempts are temporarily limited")
	}
	var wire struct {
		Method string `json:"method"`
		Code   string `json:"code"`
	}
	if err := decodeStrict(req.Approval, &wire); err != nil || wire.Method != "totp" || len(wire.Code) != 6 {
		v.failures[req.Workflow] = append(v.failures[req.Workflow], now)
		v.mu.Unlock()
		return reject(CodeInvalid, "TOTP approval is malformed")
	}
	codeValid := true
	for _, ch := range wire.Code {
		if ch < '0' || ch > '9' {
			codeValid = false
		}
	}
	if !codeValid {
		wire.Code = "000000"
	}
	step := now / 30
	matched := int64(-1)
	for _, candidate := range []int64{step - 1, step, step + 1} {
		expected := hotp(p.totpSecret, uint64(candidate), 6)
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(wire.Code))
		if codeValid && equal == 1 && matched == -1 {
			matched = candidate
		}
	}
	if matched < 0 {
		v.failures[req.Workflow] = append(v.failures[req.Workflow], now)
		v.mu.Unlock()
		return reject(CodeInvalid, "TOTP code is invalid")
	}
	cacheKey := req.Workflow + "\x00" + fmt.Sprint(matched)
	if _, exists := v.totpUsed[cacheKey]; exists {
		v.mu.Unlock()
		return reject(CodeReplayed, "TOTP step was already used")
	}
	v.totpUsed[cacheKey] = (matched + 2) * 30
	v.mu.Unlock()
	return nil
}

type hmacApproval struct {
	Method string `json:"method"`
	KeyID  string `json:"keyId"`
	Nonce  string `json:"nonce"`
	TS     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

func (v *Verifier) verifyHMAC(p *Policy, req Request) error {
	var wire hmacApproval
	if err := decodeStrict(req.Approval, &wire); err != nil || wire.Method != "hmac" || !validKeyID(wire.KeyID) {
		return reject(CodeInvalid, "HMAC approval is malformed")
	}
	nonce, sig, err := decodeNonceAndSig(wire.Nonce, wire.Sig, 32)
	if err != nil {
		return reject(CodeInvalid, "HMAC approval is malformed")
	}
	if expired(wire.TS, v.now().Unix()) {
		return reject(CodeExpired, "approval timestamp is outside the allowed window")
	}
	canonical, _, err := canonicalRequest(req, wire.Nonce, wire.TS)
	if err != nil {
		return reject(CodeInvalid, "approval request cannot be canonicalized")
	}
	key, ok := p.hmacKeys[wire.KeyID]
	if !ok {
		return reject(CodeInvalid, "HMAC key is not trusted")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return reject(CodeInvalid, "HMAC signature is invalid")
	}
	return v.recordReplay("hmac", wire.KeyID, nonce, wire.TS)
}

type signatureApproval struct {
	Method    string   `json:"method"`
	Alg       string   `json:"alg"`
	KeyID     string   `json:"keyId"`
	CertChain []string `json:"certChain"`
	Nonce     string   `json:"nonce"`
	TS        int64    `json:"ts"`
	Sig       string   `json:"sig"`
}

func (v *Verifier) verifySignature(p *Policy, req Request) error {
	var wire signatureApproval
	if err := decodeStrict(req.Approval, &wire); err != nil || wire.Method != "signature" {
		return reject(CodeInvalid, "signature approval is malformed")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(req.Approval, &fields); err != nil {
		return reject(CodeInvalid, "signature approval is malformed")
	}
	_, hasKeyID := fields["keyId"]
	_, hasChain := fields["certChain"]
	if hasKeyID == hasChain || (hasKeyID && !validKeyID(wire.KeyID)) || (hasChain && len(wire.CertChain) == 0) || (wire.Alg != "ed25519" && wire.Alg != "ecdsa-p256-sha256") {
		return reject(CodeInvalid, "signature approval is malformed")
	}
	nonce, sig, err := decodeNonceAndSig(wire.Nonce, wire.Sig, 64)
	if err != nil {
		return reject(CodeInvalid, "signature approval is malformed")
	}
	now := v.now()
	if expired(wire.TS, now.Unix()) {
		return reject(CodeExpired, "approval timestamp is outside the allowed window")
	}
	canonical, _, err := canonicalRequest(req, wire.Nonce, wire.TS)
	if err != nil {
		return reject(CodeInvalid, "approval request cannot be canonicalized")
	}
	var public any
	identity := "key:" + wire.KeyID
	if wire.KeyID != "" {
		var ok bool
		public, ok = p.trustedKeys[wire.KeyID]
		if !ok {
			return reject(CodeInvalid, "signature key is not trusted")
		}
	} else {
		public, identity, err = p.certificateKey(wire.CertChain, now)
		if err != nil {
			return reject(CodeUntrustedCert, "certificate chain is not trusted")
		}
	}
	if !algorithmMatches(wire.Alg, public) {
		return reject(CodeInvalid, "signature algorithm does not match the key")
	}
	if !verifySignature(wire.Alg, public, canonical, sig) {
		return reject(CodeInvalid, "signature is invalid")
	}
	return v.recordReplay("signature", identity, nonce, wire.TS)
}

func (p *Policy) certificateKey(chain []string, now time.Time) (any, string, error) {
	if p.roots == nil || len(chain) == 0 || len(chain) > 3 {
		return nil, "", errors.New("untrusted certificate chain")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, encoded := range chain {
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, "", err
		}
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, "", err
		}
	}
	leaf := certs[0]
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 15}) && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return nil, "", errors.New("leaf cannot sign")
		}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, "", err
	}
	if len(p.allowedSubjects) > 0 && !subjectAllowed(leaf, p.allowedSubjects) {
		return nil, "", errors.New("leaf subject is not allowed")
	}
	hash := sha256.Sum256(leaf.Raw)
	return leaf.PublicKey, "cert:" + base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func (v *Verifier) recordReplay(method, identity string, nonce []byte, ts int64) error {
	now := v.now().Unix()
	key := method + "\x00" + identity + "\x00" + base64.RawURLEncoding.EncodeToString(nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pruneLocked(now)
	if _, exists := v.replayed[key]; exists {
		return reject(CodeReplayed, "approval nonce was already used")
	}
	v.replayed[key] = ts + approvalTimeTolerance
	return nil
}

func (v *Verifier) pruneLocked(now int64) {
	for key, expiry := range v.replayed {
		if now > expiry {
			delete(v.replayed, key)
		}
	}
	for key, expiry := range v.totpUsed {
		if now > expiry {
			delete(v.totpUsed, key)
		}
	}
	for workflow, failures := range v.failures {
		kept := failures[:0]
		for _, at := range failures {
			if at >= now-300 {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(v.failures, workflow)
		} else {
			v.failures[workflow] = kept
		}
	}
}

func canonicalRequest(req Request, nonce string, ts int64) ([]byte, json.RawMessage, error) {
	params, err := NormalizeParams(req.ParamsRaw)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := decodeJSON(params)
	if err != nil {
		return nil, nil, err
	}
	var ref any
	if req.Ref != "" {
		ref = req.Ref
	}
	value := map[string]any{"agentId": req.AgentID, "nonce": nonce, "params": decoded, "ref": ref, "ts": json.Number(fmt.Sprint(ts)), "v": json.Number("1"), "workflow": req.Workflow}
	canonical, err := signing.CanonicalJSON(value)
	return canonical, params, err
}

func decodeJSON(raw []byte) (any, error) {
	value, err := decodeJSONRaw(raw)
	if err != nil {
		return nil, err
	}
	return normalizeNumbers(value)
}

func decodeJSONRaw(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func normalizeNumbers(value any) (any, error) {
	switch x := value.(type) {
	case json.Number:
		n, err := exactSafeInteger(x.String())
		if err != nil {
			return nil, err
		}
		return json.Number(n.String()), nil
	case []any:
		for i := range x {
			n, err := normalizeNumbers(x[i])
			if err != nil {
				return nil, err
			}
			x[i] = n
		}
	case map[string]any:
		for key, item := range x {
			n, err := normalizeNumbers(item)
			if err != nil {
				return nil, err
			}
			x[key] = n
		}
	}
	return value, nil
}

func exactSafeInteger(s string) (*big.Int, error) {
	negative := false
	if strings.HasPrefix(s, "-") {
		negative = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		return nil, errors.New("invalid JSON number")
	}
	exponent := int64(0)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exp, err := strconvParseExponent(s[i+1:])
		if err != nil {
			return nil, err
		}
		exponent = exp
		s = s[:i]
	}
	fraction := 0
	if i := strings.IndexByte(s, '.'); i >= 0 {
		fraction = len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	if s == "" {
		return nil, errors.New("invalid JSON number")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid JSON number")
		}
	}
	coefficient, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("invalid JSON number")
	}
	if coefficient.Sign() == 0 {
		return big.NewInt(0), nil
	}
	scale := exponent - int64(fraction)
	if scale < 0 {
		remove := -scale
		if remove > int64(len(s)) {
			return nil, errors.New("params numbers must be integers")
		}
		for i := int64(0); i < remove; i++ {
			if s[len(s)-1-int(i)] != '0' {
				return nil, errors.New("params numbers must be integers")
			}
		}
		coefficient.Quo(coefficient, new(big.Int).Exp(big.NewInt(10), big.NewInt(remove), nil))
	} else if scale > 0 {
		if scale > 16 {
			return nil, errors.New("params integer is outside the safe range")
		}
		coefficient.Mul(coefficient, new(big.Int).Exp(big.NewInt(10), big.NewInt(scale), nil))
	}
	if negative {
		coefficient.Neg(coefficient)
	}
	limit := big.NewInt(canonicalMaxInteger)
	if new(big.Int).Abs(new(big.Int).Set(coefficient)).Cmp(limit) > 0 {
		return nil, errors.New("params integer is outside the safe range")
	}
	return coefficient, nil
}

func strconvParseExponent(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("invalid JSON exponent")
	}
	var n int64
	for i, c := range s {
		if i == 0 && (c == '-' || c == '+') {
			continue
		}
		if c < '0' || c > '9' {
			return 0, errors.New("invalid JSON exponent")
		}
		if n < 100000 {
			n = n*10 + int64(c-'0')
		}
	}
	if strings.HasPrefix(s, "-") {
		return -n, nil
	}
	return n, nil
}

func decodeStrict(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func decodeNonceAndSig(nonceText, sigText string, sigLen int) ([]byte, []byte, error) {
	if !validRawURLBase64(nonceText) || !validRawURLBase64(sigText) {
		return nil, nil, errors.New("padding is forbidden")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(nonceText)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return nil, nil, errors.New("invalid nonce")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigText)
	if err != nil || len(sig) != sigLen {
		return nil, nil, errors.New("invalid signature size")
	}
	return nonce, sig, nil
}

func validRawURLBase64(text string) bool {
	if text == "" {
		return false
	}
	for _, ch := range []byte(text) {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func verifySignature(alg string, public any, message, sig []byte) bool {
	switch alg {
	case "ed25519":
		key, ok := public.(ed25519.PublicKey)
		return ok && ed25519.Verify(key, message, sig)
	case "ecdsa-p256-sha256":
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		digest := sha256.Sum256(message)
		return ecdsa.Verify(key, digest[:], r, s)
	default:
		return false
	}
}

func algorithmMatches(alg string, key any) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return alg == "ed25519"
	case *ecdsa.PublicKey:
		return alg == "ecdsa-p256-sha256" && k.Curve == elliptic.P256()
	default:
		return false
	}
}

func supportedPublicKey(key any) bool {
	return algorithmMatches("ed25519", key) || algorithmMatches("ecdsa-p256-sha256", key)
}

// decodeTOTPSecret ignores presentation whitespace and padding as required by the file format.
func decodeTOTPSecret(text string) ([]byte, error) {
	clean := strings.Builder{}
	for _, r := range text {
		if r == '=' || unicode.IsSpace(r) {
			continue
		}
		if r > 127 {
			return nil, errors.New("secret is not base32")
		}
		clean.WriteRune(r)
	}
	secret, err := decodeBase32NoPad(strings.ToUpper(clean.String()))
	if err != nil || len(secret) < 16 {
		return nil, errors.New("secret must decode to at least 16 bytes")
	}
	return secret, nil
}

func decodeBase32NoPad(text string) ([]byte, error) {
	var out []byte
	var buffer uint32
	bits := uint(0)
	for _, ch := range []byte(text) {
		var value byte
		switch {
		case ch >= 'A' && ch <= 'Z':
			value = ch - 'A'
		case ch >= '2' && ch <= '7':
			value = ch - '2' + 26
		default:
			return nil, errors.New("invalid base32 character")
		}
		buffer = (buffer << 5) | uint32(value)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buffer>>bits))
			buffer &= (1 << bits) - 1
		}
	}
	if buffer != 0 || (len(text)%8 != 0 && len(text)%8 != 2 && len(text)%8 != 4 && len(text)%8 != 5 && len(text)%8 != 7) {
		return nil, errors.New("invalid base32 encoding")
	}
	return out, nil
}

func hotp(secret []byte, counter uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	h := hmac.New(sha1.New, secret)
	_, _ = h.Write(message[:])
	digest := h.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < digits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func readYAMLStringMap(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := yaml.Unmarshal(b, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, errors.New("expected a YAML mapping")
	}
	return values, nil
}

func validKeyID(id string) bool {
	return utf8.ValidString(id) && utf8.RuneCountInString(id) >= 1 && utf8.RuneCountInString(id) <= 128
}

func expired(ts, now int64) bool {
	return ts < now-approvalTimeTolerance || ts > now+approvalTimeTolerance
}

func reject(code, message string) error { return &Rejection{Code: code, Message: message} }

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func subjectAllowed(cert *x509.Certificate, globs []string) bool {
	values := []string{cert.Subject.CommonName}
	values = append(values, cert.DNSNames...)
	values = append(values, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		values = append(values, uri.String())
	}
	for _, value := range values {
		for _, glob := range globs {
			if starMatch(glob, value) {
				return true
			}
		}
	}
	return false
}

func starMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	pos := 0
	if parts[0] != "" {
		if !strings.HasPrefix(value, parts[0]) {
			return false
		}
		pos = len(parts[0])
	}
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		i := strings.Index(value[pos:], part)
		if i < 0 {
			return false
		}
		pos += i + len(part)
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(value[pos:], last)
}
