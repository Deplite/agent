package apiclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/signing"
)

type Event struct {
	Name string
	Data json.RawMessage
}

// Stream opens an SSE connection to /v1/agent/stream and delivers events
// on out until ctx is done or the connection drops. Returns the cause of
// termination so the caller can decide whether to reconnect.
func (c *Client) Stream(ctx context.Context, signer Signer, out chan<- Event) error {
	const path = "/agent/stream"

	now := c.Now
	if now == nil {
		now = time.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	nonce, err := signing.NewNonce()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	signedPath := path
	if req.URL != nil && req.URL.Path != "" {
		signedPath = req.URL.Path
	}
	canonical := signing.BuildCanonical(signing.SignableRequest{
		Timestamp: ts, Nonce: nonce, Method: "GET", Path: signedPath,
	})
	sig := base64.StdEncoding.EncodeToString(signer.Sign(canonical))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("x-deplite-features", "probe")
	req.Header.Set("x-agent-id", signer.AgentID())
	req.Header.Set("x-timestamp", ts)
	req.Header.Set("x-nonce", nonce)
	req.Header.Set("x-signature", sig)

	// SSE needs no per-request timeout; rely on ctx for shutdown.
	cli := &http.Client{Transport: c.HTTPClient.Transport}
	res, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("apiclient: stream connect: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return &APIError{StatusCode: res.StatusCode, Body: string(body)}
	}

	return parseSSE(ctx, res.Body, out)
}

func parseSSE(ctx context.Context, body io.Reader, out chan<- Event) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var name string
	var dataLines []string

	flush := func() {
		if name == "" && len(dataLines) == 0 {
			return
		}
		data := strings.Join(dataLines, "\n")
		evt := Event{Name: name, Data: json.RawMessage(data)}
		select {
		case <-ctx.Done():
		case out <- evt:
		}
		name = ""
		dataLines = dataLines[:0]
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, ":"): // comment / keepalive
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("apiclient: stream read: %w", err)
	}
	flush()
	return io.EOF
}
