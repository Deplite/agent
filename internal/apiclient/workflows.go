package apiclient

import "context"

// ReportedWorkflow is the catalog projection of a workflow that the
// agent sends to the backend. Execution body (step.run, env values,
// working-directory, shell, secret values, secret.scope, output.from)
// is deliberately omitted — those stay on the agent's disk.
type ReportedWorkflow struct {
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Version       string           `json:"version,omitempty"`
	SchemaVersion int              `json:"schemaVersion,omitempty"`
	VerboseSteps  []string         `json:"verboseSteps"`
	SecretsKeys   []string         `json:"secretsKeys"`
	Secrets       []ReportedSecret `json:"secrets,omitempty"`
	Params        []ReportedParam  `json:"params,omitempty"`
	Outputs       []ReportedOutput `json:"outputs,omitempty"`
	Retry         *ReportedRetry   `json:"retry,omitempty"`
	Steps         []ReportedStep   `json:"steps,omitempty"`
	On            *ReportedOn      `json:"on,omitempty"`
}

// ReportedOn mirrors the yaml on: block so the console can show what the
// host has declared. Absent means the workflow declines outside calls.
type ReportedOn struct {
	Webhook *ReportedOnWebhook `json:"webhook,omitempty"`
}

// ReportedOnWebhook carries the declared ref patterns. An omitted list
// means every ref.
type ReportedOnWebhook struct {
	Refs     []string          `json:"refs,omitempty"`
	Approval *ReportedApproval `json:"approval,omitempty"`
}

// ReportedApproval contains only the enabled method names, never local file settings.
type ReportedApproval struct {
	Methods []string `json:"methods"`
}

type ReportedParam struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Options     []string `json:"options,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
}

type ReportedOutput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type ReportedSecret struct {
	Name        string `json:"name"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

type ReportedRetry struct {
	MaxAttempts         int    `json:"maxAttempts"`
	Backoff             string `json:"backoff,omitempty"`
	InitialDelaySeconds int    `json:"initialDelaySeconds,omitempty"`
	MaxDelaySeconds     int    `json:"maxDelaySeconds,omitempty"`
}

type ReportedStep struct {
	ID              string         `json:"id,omitempty"`
	Name            string         `json:"name"`
	TimeoutMinutes  int            `json:"timeoutMinutes,omitempty"`
	Verbose         bool           `json:"verbose,omitempty"`
	ContinueOnError bool           `json:"continueOnError,omitempty"`
	Retry           *ReportedRetry `json:"retry,omitempty"`
}

type reportRequest struct {
	Workflows []ReportedWorkflow `json:"workflows"`
}

// ReportResponse is per-workflow: a rejection costs that workflow its
// catalog entry, not the report. Count is the resulting catalog size,
// which can exceed len(Accepted) because a rejected workflow keeps
// whatever entry it already had.
type ReportResponse struct {
	Count    int                `json:"count"`
	Accepted []string           `json:"accepted"`
	Rejected []RejectedWorkflow `json:"rejected,omitempty"`
}

// RejectedWorkflow is one workflow the backend would not catalog. Code is
// "invalid_schema" or "quota_exceeded" today; treat anything else as a
// plain refusal.
type RejectedWorkflow struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

func (c *Client) ReportWorkflows(ctx context.Context, s Signer, wfs []ReportedWorkflow) (ReportResponse, error) {
	if wfs == nil {
		wfs = []ReportedWorkflow{}
	}
	var res ReportResponse
	err := c.SignedRequest(ctx, s, "POST", "/agent/workflows/report", reportRequest{Workflows: wfs}, &res)
	return res, err
}
