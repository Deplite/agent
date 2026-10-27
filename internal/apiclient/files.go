package apiclient

import "context"

type PresignUploadRequest struct {
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	CleanupRule string `json:"cleanupRule,omitempty"`
	TTLSeconds  int    `json:"ttlSeconds,omitempty"`
}

type PresignUploadResponse struct {
	FileID        string            `json:"fileId"`
	UploadURL     string            `json:"uploadUrl"`
	Method        string            `json:"method,omitempty"`
	UploadHeaders map[string]string `json:"headers,omitempty"`
	ExpiresInSec  int               `json:"expiresInSeconds,omitempty"`
}

type FileMeta struct {
	ID          string `json:"id"`
	BindingID   string `json:"bindingId"`
	JobID       string `json:"jobId,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Status      string `json:"status,omitempty"`
	CleanupRule string `json:"cleanupRule,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}

func (c *Client) PresignJobUpload(ctx context.Context, s Signer, jobID string, req PresignUploadRequest) (PresignUploadResponse, error) {
	var res PresignUploadResponse
	err := c.SignedRequest(ctx, s, "POST", "/agent/jobs/"+jobID+"/files/presign-upload", req, &res)
	return res, err
}

func (c *Client) CompleteUpload(ctx context.Context, s Signer, fileID string) (FileMeta, error) {
	var res FileMeta
	err := c.SignedRequest(ctx, s, "POST", "/agent/files/"+fileID+"/complete", nil, &res)
	return res, err
}

type DownloadURLResponse struct {
	DownloadURL  string `json:"downloadUrl"`
	ExpiresInSec int    `json:"expiresInSeconds"`
}

func (c *Client) GetDownloadURL(ctx context.Context, s Signer, fileID string) (DownloadURLResponse, error) {
	var res DownloadURLResponse
	err := c.SignedRequest(ctx, s, "GET", "/agent/files/"+fileID+"/download-url", nil, &res)
	return res, err
}

func (c *Client) GetFile(ctx context.Context, s Signer, fileID string) (FileMeta, error) {
	var res FileMeta
	err := c.SignedRequest(ctx, s, "GET", "/agent/files/"+fileID, nil, &res)
	return res, err
}

func (c *Client) DeleteFile(ctx context.Context, s Signer, fileID string) error {
	return c.SignedRequest(ctx, s, "DELETE", "/agent/files/"+fileID, nil, nil)
}
