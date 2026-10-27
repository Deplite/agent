package apiclient

import "context"

type LogStream string

const (
	LogStreamRaw    LogStream = "raw"
	LogStreamSystem LogStream = "system"
)

type LogLevel string

const (
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type LogItem struct {
	Seq      int       `json:"seq"`
	Stream   LogStream `json:"stream"`
	StepName *string   `json:"stepName,omitempty"`
	Level    LogLevel  `json:"level,omitempty"`
	Content  string    `json:"content"`
}

type LogsResponse struct {
	Accepted int `json:"accepted"`
}

func (c *Client) AppendJobLogs(ctx context.Context, s Signer, jobID string, items []LogItem) (LogsResponse, error) {
	var res LogsResponse
	err := c.SignedRequest(ctx, s, "POST", "/agent/jobs/"+jobID+"/logs", map[string]any{"items": items}, &res)
	return res, err
}

type JobStatus string

const (
	JobRunning  JobStatus = "running"
	JobSuccess  JobStatus = "success"
	JobFailed   JobStatus = "failed"
	JobTimeout  JobStatus = "timeout"
	JobRejected JobStatus = "rejected"
)

type JobResult struct {
	Status            JobStatus      `json:"status"`
	ExitCode          *int           `json:"exitCode,omitempty"`
	ErrorMessage      string         `json:"errorMessage,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	LimitType         string         `json:"limitType,omitempty"`
	RetryAfterSeconds *int           `json:"retryAfterSeconds,omitempty"`
	BypassedLimits    []string       `json:"bypassedLimits,omitempty"`
	Output            map[string]any `json:"output,omitempty"`
}

type JobResultResponse struct {
	OK     bool      `json:"ok"`
	Status JobStatus `json:"status,omitempty"`
}

func (c *Client) ReportJobResult(ctx context.Context, s Signer, jobID string, r JobResult) (JobResultResponse, error) {
	var res JobResultResponse
	err := c.SignedRequest(ctx, s, "POST", "/agent/jobs/"+jobID+"/result", r, &res)
	return res, err
}
