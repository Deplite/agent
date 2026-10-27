package agent

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/approval"
	"github.com/Deplite/agent/internal/workflow"
)

type paramValidationError struct {
	err error
}

func (e *paramValidationError) Error() string { return "param validation: " + e.err.Error() }
func (e *paramValidationError) Unwrap() error { return e.err }

func verifyWorkflowApproval(verifier *approval.Verifier, wf *workflow.Workflow, agentID string, payload apiclient.DeployPayload) (map[string]any, string, string, error) {
	var supplied map[string]any
	raw := payload.ParamsRaw
	if len(strings.TrimSpace(string(raw))) == 0 {
		raw = json.RawMessage(`{}`)
		if payload.Params != nil {
			encoded, err := json.Marshal(payload.Params)
			if err != nil {
				return nil, "", "", &paramValidationError{err: err}
			}
			raw = encoded
		}
	}
	if err := json.Unmarshal(raw, &supplied); err != nil {
		return nil, "", "", &paramValidationError{err: err}
	}
	for key := range supplied {
		if strings.HasPrefix(key, "DEPLITE_") || key == "registry_token" {
			delete(supplied, key)
		}
	}
	resolved, err := wf.ResolveParams(supplied)
	if err != nil {
		return nil, "", "", &paramValidationError{err: err}
	}
	if err := verifier.Verify(wf.ApprovalPolicy(), approval.Request{
		AgentID:   agentID,
		Workflow:  payload.WorkflowName,
		ParamsRaw: raw,
		Ref:       payload.Ref,
		Approval:  payload.Approval,
	}); err != nil {
		return nil, "", "", err
	}
	method, keyID := approvalAuditInfo(payload.Approval)
	return resolved, method, keyID, nil
}

func approvalAuditInfo(raw json.RawMessage) (string, string) {
	var wire struct {
		Method    string   `json:"method"`
		KeyID     string   `json:"keyId"`
		CertChain []string `json:"certChain"`
	}
	if json.Unmarshal(raw, &wire) != nil {
		return "unknown", "unknown"
	}
	identity := wire.KeyID
	if wire.Method == "totp" {
		identity = "totp"
	}
	if identity == "" && len(wire.CertChain) > 0 {
		if der, err := base64.StdEncoding.DecodeString(wire.CertChain[0]); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				identity = cert.Subject.CommonName
				if identity == "" {
					identity = cert.Subject.String()
				}
			}
		}
	}
	if identity == "" {
		identity = "unknown"
	}
	return safeAuditValue(wire.Method), safeAuditValue(identity)
}

func safeAuditValue(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, value)
}
