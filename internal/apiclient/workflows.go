package apiclient

import (
	"context"
	"sort"
	"strings"
)

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
	Invalid   []InvalidWorkflow  `json:"invalid"`
}

// InvalidWorkflow describes a workflow excluded from the reported catalog.
type InvalidWorkflow struct {
	Name   string   `json:"name"`
	Code   string   `json:"code"`
	Reason string   `json:"reason"`
	Files  []string `json:"files"`
}

// Rejection affects that workflow's catalog entry, not the whole report. Existing
// entries for rejected workflows may remain, so Count can exceed len(Accepted).
// Count is runnable workflows after invalid names are excluded. Invalid lists
// names recorded by the backend and is nil on older versions.
type ReportResponse struct {
	Count    int                `json:"count"`
	Accepted []string           `json:"accepted"`
	Rejected []RejectedWorkflow `json:"rejected,omitempty"`
	Invalid  []string           `json:"invalid"`
}

// RejectedWorkflow is one workflow the backend would not catalog. Code is
// "invalid_schema" or "quota_exceeded" today; treat anything else as a
// plain refusal.
type RejectedWorkflow struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

func (c *Client) ReportWorkflows(ctx context.Context, s Signer, wfs []ReportedWorkflow, invalid []InvalidWorkflow) (ReportResponse, error) {
	if wfs == nil {
		wfs = []ReportedWorkflow{}
	}
	invalid = normalizeInvalidWorkflows(invalid)
	var res ReportResponse
	err := c.SignedRequest(ctx, s, "POST", "/agent/workflows/report", reportRequest{Workflows: wfs, Invalid: invalid}, &res)
	return res, err
}

func normalizeInvalidWorkflows(invalid []InvalidWorkflow) []InvalidWorkflow {
	result := make([]InvalidWorkflow, 0, len(invalid))
	for _, item := range invalid {
		if !utf16LengthBetween(item.Name, 1, 128) || !utf16LengthBetween(item.Code, 1, 64) {
			continue
		}
		item.Reason = truncateUTF16(item.Reason, 500)
		if !utf16LengthBetween(item.Reason, 1, 500) {
			continue
		}
		files := item.Files
		item.Files = make([]string, 0, min(len(files), 20))
		for _, path := range files {
			if !utf16LengthBetween(path, 1, 255) {
				continue
			}
			if len(item.Files) == 20 {
				break
			}
			item.Files = append(item.Files, path)
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		return result[i].Reason < result[j].Reason
	})
	if len(result) > 100 {
		result = result[:100]
	}
	return result
}

func utf16LengthBetween(value string, minimum, maximum int) bool {
	length := 0
	for _, r := range value {
		length++
		if r > 0xFFFF {
			length++
		}
		if length > maximum {
			return false
		}
	}
	return length >= minimum
}

func truncateUTF16(value string, maximum int) string {
	var result strings.Builder
	length := 0
	for _, r := range value {
		units := 1
		if r > 0xFFFF {
			units = 2
		}
		if length+units > maximum {
			break
		}
		result.WriteRune(r)
		length += units
	}
	return result.String()
}
