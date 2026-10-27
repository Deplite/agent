package apiclient

import "context"

type EnrollRequest struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
	PublicKey    string `json:"publicKey"`
}

type EnrollResponse struct {
	AgentID            string `json:"agentId"`
	OrganizationID     string `json:"organizationId"`
	ServerPublicKeyPEM string `json:"serverPublicKey"`
}

func (c *Client) Enroll(ctx context.Context, installCode string, req EnrollRequest) (EnrollResponse, error) {
	var res EnrollResponse
	if err := c.BearerRequest(ctx, installCode, "POST", "/agent/enroll", req, &res); err != nil {
		return EnrollResponse{}, err
	}
	return res, nil
}

type IdentityPatch struct {
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

func (c *Client) UpdateIdentity(ctx context.Context, s Signer, patch IdentityPatch) error {
	return c.SignedRequest(ctx, s, "PATCH", "/agent/identity", patch, nil)
}

func (c *Client) Heartbeat(ctx context.Context, s Signer) error {
	return c.SignedRequest(ctx, s, "POST", "/agent/heartbeat", nil, nil)
}

// HeartbeatProbe acknowledges a stream probe with a signed heartbeat body.
func (c *Client) HeartbeatProbe(ctx context.Context, s Signer, probeID string) error {
	return c.SignedRequest(ctx, s, "POST", "/agent/heartbeat", struct {
		ProbeID string `json:"probeId"`
	}{ProbeID: probeID}, nil)
}
