//go:build e2e

// End-to-end test: the real deplite-agent binary against a mock backend.
//
// Run with:
//
//	go test -tags=e2e ./e2e/...
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	installCode  = "e2e-install-code-1"
	jobID        = "job-e2e-1"
	workflowName = "e2e-echo"

	otaWorkflowName = "e2e-ota"
	signedJobID     = "job-e2e-signed"
	forgedJobID     = "job-e2e-forged"
	approvedJobID   = "job-e2e-approval-ok"
	missingJobID    = "job-e2e-approval-missing"
	approvalWFName  = "e2e-approval"
)

const workflowYAML = `name: e2e-echo
description: E2E test workflow
params:
  - name: who
    type: string
    required: true
outputs:
  - name: greeting
    type: string
    from: main.greeting
steps:
  - id: main
    name: greet
    verbose: true
    run: |
      echo "hello ${DEPLITE_PARAM_WHO}"
      echo "greeting=hello ${DEPLITE_PARAM_WHO}" >> "$DEPLITE_OUTPUT"
`

// The OTA workflow deliberately does no verification of its own: the agent
// checks the artifact before any step runs, so reaching `applied` at all is
// the assertion.
const otaWorkflowYAML = `name: e2e-ota
description: E2E OTA artifact workflow
params:
  - name: artifact
    type: string
    required: true
    max: 8192
  - name: checksum_sha256
    type: string
    pattern: '^[a-f0-9]{64}$'
  - name: signature
    type: string
    max: 8192
  - name: artifact_public_key
    type: string
    max: 4096
steps:
  - name: apply
    verbose: true
    run: |
      test -s "$DEPLITE_PARAM_ARTIFACT"
      echo "applied sig=${DEPLITE_ARTIFACT_SIGNATURE_VERIFIED:-unset} sum=${DEPLITE_ARTIFACT_CHECKSUM_VERIFIED:-unset}"
`

const approvalWorkflowYAML = `name: e2e-approval
params:
  - name: target
    type: string
    required: true
on:
  webhook:
    approval:
      hmac:
        keys-file: %s
steps:
  - name: guarded
    run: test "$DEPLITE_PARAM_TARGET" = production
`

func TestAgentEndToEnd(t *testing.T) {
	bin := buildAgent(t)
	mock := newMockBackend(t, installCode)
	mock.probeID = "probe-job-e2e"
	mock.prepareDeploy(jobID, workflowName, map[string]any{"who": "e2e"}, true)

	dataDir := t.TempDir()
	logDir := t.TempDir()
	wfDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wfDir, "e2e-echo.yml"), []byte(workflowYAML), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "e2e-ota.yml"), []byte(otaWorkflowYAML), 0o600); err != nil {
		t.Fatalf("write ota workflow: %v", err)
	}
	approvalKey := []byte("01234567890123456789012345678901")
	approvalKeyDir := t.TempDir()
	approvalKeysPath := filepath.Join(approvalKeyDir, "approval-keys.yaml")
	if err := os.WriteFile(approvalKeysPath, []byte("e2e-key: "+base64.StdEncoding.EncodeToString(approvalKey)+"\n"), 0o600); err != nil {
		t.Fatalf("write approval key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "e2e-approval.yml"), []byte(fmt.Sprintf(approvalWorkflowYAML, approvalKeysPath)), 0o600); err != nil {
		t.Fatalf("write approval workflow: %v", err)
	}
	params := map[string]any{"target": "production"}
	approvalWire := signApproval(t, approvalKey, "agt_e2e_1", approvalWFName, params)
	mock.prepareDeployWithApproval(approvedJobID, approvalWFName, params, false, approvalWire)
	mock.prepareDeploy(missingJobID, approvalWFName, params, false)
	keyDir := t.TempDir()
	trusted := queueSignedDeploys(t, mock, keyDir)

	install := exec.Command(bin, "install",
		"--no-service",
		"--code", installCode,
		"--base-url", mock.baseURL(),
		"--data-dir", dataDir,
		"--name", "e2e-agent")
	install.Env = cleanEnv()
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	mock.mu.Lock()
	enrolls, enrollName := mock.enrolls, mock.enrollName
	mock.mu.Unlock()
	if enrolls != 1 {
		t.Fatalf("enrolls = %d, want 1", enrolls)
	}
	if enrollName != "e2e-agent" {
		t.Fatalf("enroll name = %q, want e2e-agent", enrollName)
	}

	start := exec.Command(bin, "start",
		"--data-dir", dataDir,
		"--workflows-dir", wfDir,
		"--heartbeat", "1s")
	start.Env = cleanEnv("DEPLITE_LOG_DIR="+logDir, "DEPLITE_ARTIFACT_KEY_DIR="+keyDir)
	var agentOut lockedBuffer
	start.Stdout = &agentOut
	start.Stderr = &agentOut
	if err := start.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() {
		if start.Process != nil {
			_ = start.Process.Kill()
		}
	})

	results := waitForTerminalResult(t, mock, jobID, &agentOut)

	if results[0].Status != "running" {
		t.Errorf("first result status = %q, want running", results[0].Status)
	}
	final := results[len(results)-1]
	if final.Status != "success" {
		t.Errorf("final result status = %q, want success (error: %s)", final.Status, final.ErrorMessage)
	}
	if final.ExitCode == nil || *final.ExitCode != 0 {
		t.Errorf("final exit code = %v, want 0", final.ExitCode)
	}
	if got, _ := final.Output["greeting"].(string); got != "hello e2e" {
		t.Errorf("output greeting = %q, want %q", got, "hello e2e")
	}

	if !containsLine(mock.jobLogContents(jobID, "raw"), "hello e2e") {
		t.Errorf("raw log stream missing %q (debug+verbose should ship raw output)", "hello e2e")
	}
	waitForProbeAck(t, mock, mock.probeID)
	approved := waitForTerminalResult(t, mock, approvedJobID, &agentOut)
	if final := approved[len(approved)-1]; final.Status != "success" {
		t.Errorf("approved workflow = %q, want success (error: %s)", final.Status, final.ErrorMessage)
	}
	if !containsLine(mock.jobLogContents(approvedJobID, "system"), "approval verified (method=hmac, keyId=e2e-key)") {
		t.Errorf("approval system log missing verification record: %v", mock.jobLogContents(approvedJobID, "system"))
	}
	missing := waitForTerminalResult(t, mock, missingJobID, &agentOut)
	if final := missing[len(missing)-1]; final.Status != "rejected" || final.Reason != "approval_required" {
		t.Errorf("approval-free workflow result = %q/%q, want rejected/approval_required", final.Status, final.Reason)
	}

	verifyArtifactGate(t, mock, trusted, &agentOut)
	verifySideEffects(t, mock)
	shutdown(t, start, &agentOut)
}

func signApproval(t *testing.T, key []byte, agentID, workflowName string, params map[string]any) []byte {
	t.Helper()
	nonce := base64.RawURLEncoding.EncodeToString([]byte("e2e-nonce-123456"))
	ts := time.Now().Unix()
	canonical := []byte(fmt.Sprintf(`{"agentId":"%s","nonce":"%s","params":{"target":"%s"},"ref":null,"ts":%d,"v":1,"workflow":"%s"}`, agentID, nonce, params["target"], ts, workflowName))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return []byte(fmt.Sprintf(`{"method":"hmac","keyId":"e2e-key","nonce":"%s","ts":%d,"sig":"%s"}`, nonce, ts, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
}

func waitForProbeAck(t *testing.T, mock *mockBackend, probeID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mock.mu.Lock()
		acked, advertised := false, false
		for _, got := range mock.probeAcks {
			acked = acked || got == probeID
		}
		for _, got := range mock.streamFeatures {
			advertised = advertised || got == "probe"
		}
		dispatched := len(mock.results[probeID]) > 0
		mock.mu.Unlock()
		if dispatched {
			t.Fatalf("probe %q was dispatched as a job", probeID)
		}
		if acked && advertised {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("probe %q was not acknowledged on a probe-capable stream", probeID)
}

// queueSignedDeploys installs a trusted public key on the device and queues
// two OTA jobs: one signed by that key and one signed by a key the device has
// never seen. It returns the trusted key's path.
func queueSignedDeploys(t *testing.T, mock *mockBackend, keyDir string) string {
	t.Helper()
	trustedPriv, trustedPub := generateKeyPair(t)
	keyPath := filepath.Join(keyDir, "app.pub")
	if err := os.WriteFile(keyPath, []byte(trustedPub), 0o600); err != nil {
		t.Fatalf("write trusted key: %v", err)
	}
	forgedPriv, forgedPub := generateKeyPair(t)

	artifact := []byte("deplite-e2e-artifact-payload")
	sum := sha256.Sum256(artifact)
	checksum := hex.EncodeToString(sum[:])

	mock.prepareDeploy(signedJobID, otaWorkflowName, map[string]any{
		"artifact":            mock.serveBlob("file-signed", artifact),
		"checksum_sha256":     checksum,
		"signature":           signBlob(t, trustedPriv, artifact),
		"artifact_public_key": trustedPub,
	}, true)
	// Same bytes, same checksum, signed by an untrusted key: only the
	// signature separates this from the job above.
	mock.prepareDeploy(forgedJobID, otaWorkflowName, map[string]any{
		"artifact":            mock.serveBlob("file-forged", artifact),
		"checksum_sha256":     checksum,
		"signature":           signBlob(t, forgedPriv, artifact),
		"artifact_public_key": forgedPub,
	}, true)
	return keyPath
}

func generateKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signBlob reproduces `cosign sign-blob --key` for a P-256 key.
func signBlob(t *testing.T, priv *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func verifyArtifactGate(t *testing.T, mock *mockBackend, trustedKeyPath string, agentOut *lockedBuffer) {
	t.Helper()

	signed := waitForTerminalResult(t, mock, signedJobID, agentOut)
	if final := signed[len(signed)-1]; final.Status != "success" {
		t.Errorf("signed artifact job = %q, want success (error: %s)", final.Status, final.ErrorMessage)
	}
	if !containsLine(mock.jobLogContents(signedJobID, "system"), "artifact signature verified with local key "+trustedKeyPath) {
		t.Errorf("system log missing the verification record: %v", mock.jobLogContents(signedJobID, "system"))
	}
	// The step reads the flags the agent injected: a workflow uses them to skip
	// a cosign fallback that an older agent still needs.
	if !containsLine(mock.jobLogContents(signedJobID, "raw"), "applied sig=1 sum=1") {
		t.Errorf("verified artifact should have reached the workflow with both flags set: %v", mock.jobLogContents(signedJobID, "raw"))
	}

	forged := waitForTerminalResult(t, mock, forgedJobID, agentOut)
	final := forged[len(forged)-1]
	if final.Status != "failed" {
		t.Errorf("artifact signed by an untrusted key = %q, want failed", final.Status)
	}
	// A step that ran anyway would mean the gate is placed after execution.
	if len(mock.jobLogContents(forgedJobID, "raw")) > 0 {
		t.Errorf("a failed verification must not run any step: %v", mock.jobLogContents(forgedJobID, "raw"))
	}
}

func waitForTerminalResult(t *testing.T, mock *mockBackend, id string, agentOut *lockedBuffer) []jobResultBody {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		results := mock.jobResults(id)
		if n := len(results); n > 0 {
			switch results[n-1].Status {
			case "success", "failed", "timeout", "rejected":
				return results
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no terminal result for job %s within deadline\nagent output:\n%s", id, agentOut.String())
	return nil
}

func verifySideEffects(t *testing.T, mock *mockBackend) {
	t.Helper()
	mock.mu.Lock()
	heartbeats, identity, reports, failures := mock.heartbeats, mock.identity, mock.reportRaw, mock.authFailures
	mock.mu.Unlock()

	if heartbeats < 1 {
		t.Error("no heartbeat received")
	}
	if identity < 1 {
		t.Error("no identity patch received")
	}
	if len(failures) > 0 {
		t.Errorf("signature verification failures: %v", failures)
	}

	found := false
	for _, raw := range reports {
		if strings.Contains(raw, `"name":"e2e-echo"`) {
			found = true
		}
		// Catalog boundary: execution body must never reach the backend.
		if strings.Contains(raw, "DEPLITE_PARAM_WHO") || strings.Contains(raw, `"run"`) {
			t.Errorf("workflow report leaked step run body: %s", raw)
		}
	}
	if !found {
		t.Errorf("workflow e2e-echo never reported (reports: %v)", reports)
	}

	// The deploy-state sync fires asynchronously on stream connect.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mock.mu.Lock()
		calls := mock.desiredCalls
		mock.mu.Unlock()
		if calls >= 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("GET /agent/deploy/desired never called after stream connect")
}

func shutdown(t *testing.T, start *exec.Cmd, agentOut *lockedBuffer) {
	t.Helper()
	if err := start.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- start.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("agent exited non-zero after SIGTERM: %v\nagent output:\n%s", err, agentOut.String())
		}
	case <-time.After(20 * time.Second):
		_ = start.Process.Kill()
		<-done
		t.Errorf("agent did not exit within 20s of SIGTERM\nagent output:\n%s", agentOut.String())
	}
}

func buildAgent(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "deplite-agent")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/deplite-agent")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v\n%s", err, out)
	}
	return bin
}

// cleanEnv strips inherited DEPLITE_* vars so a developer's real agent
// config can never leak into the subprocess.
func cleanEnv(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DEPLITE_") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
