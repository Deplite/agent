package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// DesiredApp is one verified per-app deploy manifest from
// GET /agent/deploy/desired. Fields are snake_case on the wire. Current is
// nil when the server has no observed version; Desired is nil when the
// channel has no published release.
type DesiredApp struct {
	ApplicationID  string          `json:"application_id"`
	Slug           string          `json:"slug"`
	Channel        string          `json:"channel"`
	UpdateWorkflow string          `json:"update_workflow"`
	Current        *DesiredCurrent `json:"current"`
	Desired        *DesiredRelease `json:"desired"`
	MinVersion     string          `json:"min_version"`
	MinSequence    int64           `json:"min_sequence"`
	Forced         bool            `json:"forced"`
	IssuedAt       int64           `json:"issued_at"`
	Nonce          string          `json:"nonce"`
}

// DesiredCurrent is the server's observed installed release for a device.
type DesiredCurrent struct {
	ReleaseID string `json:"release_id"`
	Version   string `json:"version"`
	Sequence  int64  `json:"sequence"`
}

// DesiredRelease is the channel's latest published release a device should
// converge to.
type DesiredRelease struct {
	ReleaseID         string `json:"release_id"`
	Version           string `json:"version"`
	Sequence          int64  `json:"sequence"`
	Channel           string `json:"channel"`
	WorkflowName      string `json:"workflow_name"`
	ChecksumSHA256    string `json:"checksum_sha256"`
	Size              int64  `json:"size"`
	DownloadURL       string `json:"download_url"`
	DownloadExpiresIn int    `json:"download_expires_in"`
}

type desiredManifest struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type desiredResponse struct {
	Apps []desiredManifest `json:"apps"`
}

// GetDesiredDeploys fetches the signed per-app manifests and returns only
// the ones whose signature verifies against serverPublicKeyPEM. Manifests
// that fail verification are skipped and reported in the (non-nil) error,
// which callers may log while still using the returned slice.
func (c *Client) GetDesiredDeploys(ctx context.Context, s Signer, serverPublicKeyPEM string) ([]DesiredApp, error) {
	var res desiredResponse
	if err := c.SignedRequest(ctx, s, "GET", "/agent/deploy/desired", nil, &res); err != nil {
		return nil, err
	}
	apps := make([]DesiredApp, 0, len(res.Apps))
	var skipped []error
	for i, m := range res.Apps {
		if err := verifySignedPayload(m.Payload, m.Signature, serverPublicKeyPEM); err != nil {
			skipped = append(skipped, fmt.Errorf("desired[%d]: %w", i, err))
			continue
		}
		var app DesiredApp
		if err := json.Unmarshal(m.Payload, &app); err != nil {
			skipped = append(skipped, fmt.Errorf("desired[%d]: unmarshal: %w", i, err))
			continue
		}
		apps = append(apps, app)
	}
	return apps, errors.Join(skipped...)
}

// DeviceState is the reported lifecycle state of an app on this device.
type DeviceState string

const (
	DeviceIdle     DeviceState = "idle"
	DevicePending  DeviceState = "pending"
	DeviceUpdating DeviceState = "updating"
	DeviceFailed   DeviceState = "failed"
)

// DeviceReport is the body of POST /agent/deploy/report. Absent optionals
// are omitted so an unset value never reads as zero on the server.
type DeviceReport struct {
	ApplicationID    string      `json:"applicationId"`
	CurrentVersion   string      `json:"currentVersion,omitempty"`
	CurrentReleaseID string      `json:"currentReleaseId,omitempty"`
	CurrentSequence  *int64      `json:"currentSequence,omitempty"`
	State            DeviceState `json:"state,omitempty"`
	Error            string      `json:"error,omitempty"`
}

// ReportDeviceState reports this device's observed app state. The server
// reconciles immediately and may dispatch a new update job.
func (c *Client) ReportDeviceState(ctx context.Context, s Signer, r DeviceReport) error {
	return c.SignedRequest(ctx, s, "POST", "/agent/deploy/report", r, nil)
}
