package apiclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Deplite/agent/internal/signing"
)

// DeployPayload is the body of a 'deploy' SSE event. Field names are
// snake_case to match the backend wire format.
type DeployPayload struct {
	JobID        string          `json:"job_id"`
	WorkflowName string          `json:"workflow_name"`
	Debug        bool            `json:"debug"`
	Ref          string          `json:"ref,omitempty"`
	Params       map[string]any  `json:"params,omitempty"`
	ParamsRaw    json.RawMessage `json:"-"`
	Approval     json.RawMessage `json:"approval,omitempty"`
	IssuedAt     int64           `json:"issued_at"`
	Nonce        string          `json:"nonce"`
	Force        bool            `json:"force,omitempty"`
	ForceReason  string          `json:"force_reason,omitempty"`
	// Via names the dispatch path. The backend omits the key entirely for
	// trigger jobs, which predate the on: block, so an empty value means
	// legacy and must keep its old behavior.
	Via string `json:"via,omitempty"`
}

// ViaRun marks a job dispatched through the workflow call endpoint. Only
// these are subject to the yaml's on: block.
const ViaRun = "run"

// DeployEnvelope keeps the payload as raw bytes so verification runs over
// exactly what the server signed, including fields this agent version does
// not yet model.
type DeployEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// ParseAndVerifyDeploy verifies a deploy event's Ed25519 signature over
// the raw payload bytes, then decodes it. The server public key is the one
// persisted at enroll time. An empty signature is treated as missing.
func ParseAndVerifyDeploy(eventData []byte, serverPublicKeyPEM string) (DeployPayload, error) {
	var env DeployEnvelope
	if err := json.Unmarshal(eventData, &env); err != nil {
		return DeployPayload{}, fmt.Errorf("deploy: unmarshal envelope: %w", err)
	}
	if env.Signature == "" {
		var id struct {
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(env.Payload, &id)
		return DeployPayload{}, fmt.Errorf("deploy: missing signature for job %s", id.JobID)
	}
	if err := verifySignedPayload(env.Payload, env.Signature, serverPublicKeyPEM); err != nil {
		return DeployPayload{}, fmt.Errorf("deploy: %w", err)
	}
	var payload DeployPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return DeployPayload{}, fmt.Errorf("deploy: unmarshal payload: %w", err)
	}
	var original struct {
		Params   json.RawMessage `json:"params"`
		Approval json.RawMessage `json:"approval"`
	}
	if err := json.Unmarshal(env.Payload, &original); err != nil {
		return DeployPayload{}, fmt.Errorf("deploy: unmarshal raw fields: %w", err)
	}
	payload.ParamsRaw = append(json.RawMessage(nil), original.Params...)
	payload.Approval = append(json.RawMessage(nil), original.Approval...)
	return payload, nil
}

// verifySignedPayload checks an Ed25519 signature over the canonical form
// of raw JSON payload bytes. Both deploy events and desired manifests use
// this so unknown fields survive into the verified bytes.
func verifySignedPayload(payload json.RawMessage, signature, serverPublicKeyPEM string) error {
	if signature == "" {
		return errors.New("missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	canonical, err := signing.CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}
	return signing.VerifyEd25519PEM(serverPublicKeyPEM, canonical, sig)
}
