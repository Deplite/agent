// Package files moves job-attached files between the agent and the
// backend object store via signed URLs.
//
// Wire shapes:
//
//	input  FileRef: {"__type":"FileRef","id":"<fileId>","filename":"x","downloadUrl":"...","expiresAt":"..."}
//	output marker:  {"$file":"<relative path under DEPLITE_OUTPUT>"}
//
// WalkInputs replaces every FileRef object in a params tree with the
// local path of the downloaded file. WalkOutputs replaces every
// {"$file":...} marker in the user-written result tree with an uploaded
// FileRef object.
package files

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
)

const (
	TypeTag            = "FileRef"
	OutputFileMarker   = "$file"
	OutputManifestName = "result.json"
)

type SerializedFileRef struct {
	Type        string
	ID          string
	Filename    string
	ContentType string
	Size        int64
	DownloadURL string
	ExpiresAt   string
}

// IsFileRef detects a FileRef-shaped JSON object.
func IsFileRef(v any) (SerializedFileRef, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return SerializedFileRef{}, false
	}
	t, _ := m["__type"].(string)
	if t != TypeTag {
		return SerializedFileRef{}, false
	}
	id, _ := m["id"].(string)
	if id == "" {
		return SerializedFileRef{}, false
	}
	r := SerializedFileRef{Type: t, ID: id}
	if s, ok := m["filename"].(string); ok {
		r.Filename = s
	}
	if s, ok := m["contentType"].(string); ok {
		r.ContentType = s
	}
	if n, ok := m["size"].(float64); ok {
		r.Size = int64(n)
	}
	if s, ok := m["downloadUrl"].(string); ok {
		r.DownloadURL = s
	}
	if s, ok := m["expiresAt"].(string); ok {
		r.ExpiresAt = s
	}
	return r, true
}

type Resolver struct {
	c       *apiclient.Client
	s       apiclient.Signer
	baseDir string
	http    *http.Client
	counter int
}

func NewResolver(c *apiclient.Client, s apiclient.Signer, baseDir string) *Resolver {
	return &Resolver{c: c, s: s, baseDir: baseDir, http: &http.Client{Timeout: 0}}
}

// WalkInputs replaces every FileRef in v with its downloaded local path.
func (r *Resolver) WalkInputs(ctx context.Context, v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := IsFileRef(x); ok {
			return r.download(ctx, ref)
		}
		for k, val := range x {
			rv, err := r.WalkInputs(ctx, val)
			if err != nil {
				return nil, err
			}
			x[k] = rv
		}
		return x, nil
	case []any:
		for i, val := range x {
			rv, err := r.WalkInputs(ctx, val)
			if err != nil {
				return nil, err
			}
			x[i] = rv
		}
		return x, nil
	default:
		return v, nil
	}
}

func (r *Resolver) download(ctx context.Context, ref SerializedFileRef) (string, error) {
	url := ref.DownloadURL
	expired := false
	if ref.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, ref.ExpiresAt); err == nil && time.Until(t) < 30*time.Second {
			expired = true
		}
	}
	if url == "" || expired {
		resp, err := r.c.GetDownloadURL(ctx, r.s, ref.ID)
		if err != nil {
			return "", fmt.Errorf("refresh download url: %w", err)
		}
		url = resp.DownloadURL
	}

	if err := os.MkdirAll(r.baseDir, 0o700); err != nil {
		return "", err
	}
	r.counter++
	name := ref.Filename
	if name == "" {
		name = ref.ID
	}
	name = filepath.Base(name)
	dst := filepath.Join(r.baseDir, fmt.Sprintf("%d-%s", r.counter, name))

	status, err := r.fetch(ctx, url, dst, ref.ID)
	if err == nil {
		return dst, nil
	}
	// An OTA artifact FileRef carries no expiresAt to pre-check, so a job
	// that waited in the local queue can hit a URL the object store has
	// already expired. On a server-side rejection refresh the URL once and
	// retry; a transport error is not a stale URL, so leave it alone.
	if status < 300 {
		return "", err
	}
	fresh, ferr := r.c.GetDownloadURL(ctx, r.s, ref.ID)
	if ferr != nil {
		return "", fmt.Errorf("refresh download url: %w", ferr)
	}
	if _, err := r.fetch(ctx, fresh.DownloadURL, dst, ref.ID); err != nil {
		return "", err
	}
	return dst, nil
}

// fetch downloads url into dst and returns the HTTP status. On a non-2xx
// response err is set and status is >=300; on a transport error status is 0.
func (r *Resolver) fetch(ctx context.Context, url, dst, id string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return resp.StatusCode, fmt.Errorf("download %s: %s: %s", id, resp.Status, string(body))
	}
	f, err := os.Create(dst)
	if err != nil {
		return resp.StatusCode, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return resp.StatusCode, err
	}
	if err := f.Close(); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

type Uploader struct {
	c     *apiclient.Client
	s     apiclient.Signer
	jobID string
	http  *http.Client
}

func NewUploader(c *apiclient.Client, s apiclient.Signer, jobID string) *Uploader {
	return &Uploader{c: c, s: s, jobID: jobID, http: &http.Client{Timeout: 0}}
}

// WalkOutputs replaces every {"$file":"<rel>"} marker in v with an
// uploaded FileRef object. Paths are joined against rootDir.
func (u *Uploader) WalkOutputs(ctx context.Context, v any, rootDir string) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			if rel, ok := x[OutputFileMarker].(string); ok {
				ref, err := u.upload(ctx, filepath.Join(rootDir, rel))
				if err != nil {
					return nil, fmt.Errorf("upload %s: %w", rel, err)
				}
				return ref, nil
			}
		}
		for k, val := range x {
			rv, err := u.WalkOutputs(ctx, val, rootDir)
			if err != nil {
				return nil, err
			}
			x[k] = rv
		}
		return x, nil
	case []any:
		for i, val := range x {
			rv, err := u.WalkOutputs(ctx, val, rootDir)
			if err != nil {
				return nil, err
			}
			x[i] = rv
		}
		return x, nil
	default:
		return v, nil
	}
}

func (u *Uploader) upload(ctx context.Context, path string) (map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}

	pre, err := u.c.PresignJobUpload(ctx, u.s, u.jobID, apiclient.PresignUploadRequest{
		Filename:    filepath.Base(path),
		ContentType: "application/octet-stream",
		CleanupRule: "persistent",
	})
	if err != nil {
		return nil, fmt.Errorf("presign: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	method := pre.Method
	if method == "" {
		method = http.MethodPut
	}
	req, err := http.NewRequestWithContext(ctx, method, pre.UploadURL, f)
	if err != nil {
		return nil, err
	}
	req.ContentLength = info.Size()
	for k, v := range pre.UploadHeaders {
		req.Header.Set(k, v)
	}
	resp, err := u.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("put: %s: %s", resp.Status, string(body))
	}
	if _, err := u.c.CompleteUpload(ctx, u.s, pre.FileID); err != nil {
		return nil, fmt.Errorf("complete: %w", err)
	}
	return map[string]any{
		"__type":      TypeTag,
		"id":          pre.FileID,
		"filename":    filepath.Base(path),
		"contentType": "application/octet-stream",
		"size":        info.Size(),
	}, nil
}

// ReadManifest loads <outputDir>/result.json into a generic JSON tree.
// Returns (nil, nil) if absent or blank.
func ReadManifest(outputDir string) (any, error) {
	p := filepath.Join(outputDir, OutputManifestName)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return v, nil
}
