// Package joblog batches log lines per job and ships them to the
// backend on a timer or when the buffer fills.
package joblog

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
)

type Sink interface {
	AppendJobLogs(ctx context.Context, s apiclient.Signer, jobID string, items []apiclient.LogItem) (apiclient.LogsResponse, error)
}

type Shipper struct {
	sink        Sink
	signer      apiclient.Signer
	flushPeriod time.Duration
	maxBatch    int

	mu      sync.Mutex
	buffers map[string][]apiclient.LogItem
	seqs    map[string]int
	echo    func(stream apiclient.LogStream, stepName, content string)
}

func New(sink Sink, signer apiclient.Signer) *Shipper {
	return &Shipper{
		sink:        sink,
		signer:      signer,
		flushPeriod: time.Second,
		maxBatch:    100,
		buffers:     map[string][]apiclient.LogItem{},
		seqs:        map[string]int{},
	}
}

// Append queues one log line. Seq is auto-assigned per jobID. When
// LocalDir is set, the line is also mirrored to <LocalDir>/<jobID>/<stream>.log.
func (s *Shipper) Append(jobID string, stream apiclient.LogStream, stepName, content string, level apiclient.LogLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqs[jobID]++
	item := apiclient.LogItem{
		Seq:     s.seqs[jobID],
		Stream:  stream,
		Content: content,
		Level:   level,
	}
	if stepName != "" {
		sn := stepName
		item.StepName = &sn
	}
	s.buffers[jobID] = append(s.buffers[jobID], item)
	mirrorLocal(jobID, stream, content)
	if s.echo != nil {
		s.echo(stream, stepName, content)
	}
}

// SetEcho registers a callback that receives every line the shipper
// handles, queued or mirror-only. A local run prints step output through
// it instead of relying on the backend copy.
func (s *Shipper) SetEcho(fn func(stream apiclient.LogStream, stepName, content string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.echo = fn
}

// MirrorRaw writes a raw log line to the local mirror only, without
// queuing it for the backend. Used when a step's stdout/stderr must
// not leave the host (no debug, or the step did not opt into verbose).
func (s *Shipper) MirrorRaw(jobID, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mirrorLocal(jobID, apiclient.LogStreamRaw, content)
	if s.echo != nil {
		s.echo(apiclient.LogStreamRaw, "", content)
	}
}

func mirrorLocal(jobID string, stream apiclient.LogStream, content string) {
	if LocalDir == "" {
		return
	}
	dir := filepath.Join(LocalDir, jobID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	name := "system.log"
	if stream == apiclient.LogStreamRaw {
		name = "raw.log"
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(content + "\n")
}

// Flush ships everything queued for jobID. Safe to call concurrently
// with Append; uses a snapshot under the lock.
func (s *Shipper) Flush(ctx context.Context, jobID string) error {
	s.mu.Lock()
	items := s.buffers[jobID]
	s.buffers[jobID] = nil
	s.mu.Unlock()
	if len(items) == 0 {
		return nil
	}
	_, err := s.sink.AppendJobLogs(ctx, s.signer, jobID, items)
	return err
}

// Run is a blocking helper: ships logs for jobID on a periodic ticker
// until ctx is canceled, then performs a final flush.
func (s *Shipper) Run(ctx context.Context, jobID string) {
	ticker := time.NewTicker(s.flushPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Flush(flushCtx, jobID)
			cancel()
			return
		case <-ticker.C:
			_ = s.Flush(ctx, jobID)
		}
	}
}

// Forget drops any buffered state for jobID. Call after the job is
// fully reported so memory does not grow unbounded across runs.
func (s *Shipper) Forget(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buffers, jobID)
	delete(s.seqs, jobID)
}
