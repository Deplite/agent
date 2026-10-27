package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/approval"
	"github.com/Deplite/agent/internal/signing"
	"github.com/Deplite/agent/internal/workflow"
)

func TestApprovalGateRequiresApprovalForEveryDispatchPath(t *testing.T) {
	wf, _ := approvalWorkflow(t)
	for _, via := range []string{"", "ota"} {
		payload := apiclient.DeployPayload{
			WorkflowName: wf.Name,
			Via:          via,
			ParamsRaw:    json.RawMessage(`{"target":"prod"}`),
		}
		_, _, _, err := verifyWorkflowApproval(approval.NewVerifier(nil), &wf, "agent-1", payload)
		var rejected *approval.Rejection
		if !errors.As(err, &rejected) || rejected.Code != approval.CodeRequired {
			t.Errorf("via=%q error = %v, want %s", via, err, approval.CodeRequired)
		}
	}
}

func TestApprovalGateUsesSanitizedResolvedParams(t *testing.T) {
	wf, key := approvalWorkflow(t)
	params := json.RawMessage(`{"target":"prod","DEPLITE_JOB_ID":"forged","registry_token":"server-secret"}`)
	now := time.Unix(1792000000, 0)
	approvalWire := signHMACApproval(t, key, "agent-1", wf.Name, "", "nonce-123456789012", now.Unix(), params)
	payload := apiclient.DeployPayload{
		WorkflowName: wf.Name,
		Params:       map[string]any{"target": "prod", "DEPLITE_JOB_ID": "forged", "registry_token": "server-secret"},
		ParamsRaw:    params,
		Approval:     approvalWire,
	}
	resolved, method, keyID, err := verifyWorkflowApproval(approval.NewVerifier(func() time.Time { return now }), &wf, "agent-1", payload)
	if err != nil {
		t.Fatalf("verifyWorkflowApproval: %v", err)
	}
	if method != "hmac" || keyID != "test-key" {
		t.Fatalf("audit identity = %q/%q", method, keyID)
	}
	if resolved["target"] != "prod" || len(resolved) != 1 {
		t.Fatalf("resolved params = %#v", resolved)
	}
}

func TestApprovalGateReportsParamFailureBeforeApprovalFailure(t *testing.T) {
	wf, _ := approvalWorkflow(t)
	payload := apiclient.DeployPayload{
		WorkflowName: wf.Name,
		ParamsRaw:    json.RawMessage(`{"undeclared":"value"}`),
	}
	_, _, _, err := verifyWorkflowApproval(approval.NewVerifier(nil), &wf, "agent-1", payload)
	var paramsErr *paramValidationError
	if !errors.As(err, &paramsErr) || paramsErr.Error() != `param validation: param "undeclared": not declared` {
		t.Fatalf("error = %v, want params validation before approval_required", err)
	}
}

func approvalWorkflow(t *testing.T) (workflow.Workflow, []byte) {
	t.Helper()
	dir := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	keyPath := filepath.Join(dir, "hmac.yaml")
	if err := os.WriteFile(keyPath, []byte("test-key: "+base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "workflow.yml")
	body := fmt.Sprintf(`name: protected
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
  - name: deploy
    run: echo ok
`, keyPath)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	wf, err := workflow.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return wf, key
}

func signHMACApproval(t *testing.T, key []byte, agentID, workflowName, ref, nonce string, ts int64, rawParams json.RawMessage) json.RawMessage {
	t.Helper()
	normalized, err := approval.NormalizeParams(rawParams)
	if err != nil {
		t.Fatal(err)
	}
	var params any
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&params); err != nil {
		t.Fatal(err)
	}
	nonceWire := base64.RawURLEncoding.EncodeToString([]byte(nonce))
	request := map[string]any{
		"agentId":  agentID,
		"nonce":    nonceWire,
		"params":   params,
		"ref":      nil,
		"ts":       ts,
		"v":        1,
		"workflow": workflowName,
	}
	if ref != "" {
		request["ref"] = ref
	}
	canonical, err := signing.CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	wire, err := json.Marshal(map[string]any{
		"method": "hmac",
		"keyId":  "test-key",
		"nonce":  nonceWire,
		"ts":     ts,
		"sig":    base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestApprovalLogInfoDoesNotLogSignature(t *testing.T) {
	raw := json.RawMessage(`{"method":"hmac","keyId":"test-key","sig":"secret-signature"}`)
	method, identity := approvalAuditInfo(raw)
	if method != "hmac" || identity != "test-key" || strings.Contains(method+identity, "secret-signature") {
		t.Fatalf("audit info = %q/%q", method, identity)
	}
}
