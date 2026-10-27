package joblog

import (
	"context"
	"sync"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
)

type recordingSink struct {
	mu    sync.Mutex
	calls [][]apiclient.LogItem
}

func (r *recordingSink) AppendJobLogs(_ context.Context, _ apiclient.Signer, _ string, items []apiclient.LogItem) (apiclient.LogsResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]apiclient.LogItem, len(items))
	copy(cp, items)
	r.calls = append(r.calls, cp)
	return apiclient.LogsResponse{Accepted: len(items)}, nil
}

type fakeSigner struct{}

func (fakeSigner) AgentID() string      { return "a" }
func (fakeSigner) Sign(m []byte) []byte { return nil }

func TestFlushSendsBufferedItemsThenClears(t *testing.T) {
	sink := &recordingSink{}
	sh := New(sink, fakeSigner{})

	sh.Append("j", apiclient.LogStreamRaw, "build", "line1", apiclient.LogLevelInfo)
	sh.Append("j", apiclient.LogStreamRaw, "build", "line2", "")

	if err := sh.Flush(context.Background(), "j"); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(sink.calls) != 1 || len(sink.calls[0]) != 2 {
		t.Fatalf("calls = %+v", sink.calls)
	}
	if sink.calls[0][0].Seq != 1 || sink.calls[0][1].Seq != 2 {
		t.Fatalf("seq not monotonic: %+v", sink.calls[0])
	}

	if err := sh.Flush(context.Background(), "j"); err != nil {
		t.Fatalf("flush 2: %v", err)
	}
	if len(sink.calls) != 1 {
		t.Fatalf("empty flush still called sink: %d", len(sink.calls))
	}
}

func TestSeqIsolatedPerJob(t *testing.T) {
	sh := New(&recordingSink{}, fakeSigner{})
	sh.Append("a", apiclient.LogStreamRaw, "", "1", "")
	sh.Append("b", apiclient.LogStreamRaw, "", "1", "")
	sh.Append("a", apiclient.LogStreamRaw, "", "2", "")
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.seqs["a"] != 2 || sh.seqs["b"] != 1 {
		t.Fatalf("seqs = %v", sh.seqs)
	}
}
