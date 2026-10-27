// Package apiclient is an HTTP client for the agent API.
package apiclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/signing"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Now        func() time.Time
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("deplite: HTTP %d: %s", e.StatusCode, e.Body)
}

type Signer interface {
	AgentID() string
	Sign(message []byte) []byte
}

func (c *Client) SignedRequest(ctx context.Context, signer Signer, method, path string, reqBody, respBody any) error {
	if signer == nil {
		return errors.New("apiclient: signer is required")
	}
	if strings.ContainsRune(path, '?') {
		return &signing.ErrInvalidPath{Path: path}
	}

	var body []byte
	if reqBody != nil {
		var err error
		body, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("apiclient: marshal body: %w", err)
		}
	}

	now := c.Now
	if now == nil {
		now = time.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	nonce, err := signing.NewNonce()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("apiclient: build request: %w", err)
	}
	// The backend re-derives the canonical message from the URL path it
	// receives (including any base prefix like /v1). Sign over the same
	// path the request will carry on the wire, not the relative path the
	// caller passed in.
	signedPath := path
	if req.URL != nil && req.URL.Path != "" {
		signedPath = req.URL.Path
	}
	canonical := signing.BuildCanonical(signing.SignableRequest{
		Timestamp: ts, Nonce: nonce, Method: method, Path: signedPath, Body: body,
	})
	sig := base64.StdEncoding.EncodeToString(signer.Sign(canonical))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-agent-id", signer.AgentID())
	req.Header.Set("x-timestamp", ts)
	req.Header.Set("x-nonce", nonce)
	req.Header.Set("x-signature", sig)

	return c.do(req, respBody)
}

func (c *Client) BearerRequest(ctx context.Context, bearer, method, path string, reqBody, respBody any) error {
	var body []byte
	if reqBody != nil {
		var err error
		body, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("apiclient: marshal body: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("apiclient: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return c.do(req, respBody)
}

func (c *Client) do(req *http.Request, respBody any) error {
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("apiclient: %s %s: %w", req.Method, redact(req.URL), err)
	}
	defer res.Body.Close()
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("apiclient: read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &APIError{StatusCode: res.StatusCode, Body: string(buf)}
	}
	if respBody == nil || len(buf) == 0 {
		return nil
	}
	if err := json.Unmarshal(buf, respBody); err != nil {
		return fmt.Errorf("apiclient: decode response: %w", err)
	}
	return nil
}

// redact strips the query string so install codes or signed tokens
// never end up in error messages.
func redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.RawQuery = ""
	return c.String()
}
