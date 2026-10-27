package apiclient

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubSigner struct {
	id  string
	pri ed25519.PrivateKey
}

func (s *stubSigner) AgentID() string      { return s.id }
func (s *stubSigner) Sign(m []byte) []byte { return ed25519.Sign(s.pri, m) }

func TestStreamDeliversEvents(t *testing.T) {
	_, pri, _ := ed25519.GenerateKey(nil)
	signer := &stubSigner{id: "a", pri: pri}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-signature") == "" {
			t.Errorf("missing signature header")
		}
		if got := r.Header.Get("x-deplite-features"); got != "probe" {
			t.Errorf("x-deplite-features = %q, want probe", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("event: ping\ndata: {\"ts\":1}\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("event: deploy\ndata: {\"job_id\":\"abc\"}\n\n"))
		fl.Flush()
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	out := make(chan Event, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Stream(ctx, signer, out) }()

	for i, want := range []string{"ping", "deploy"} {
		select {
		case e := <-out:
			if e.Name != want {
				t.Fatalf("event %d name = %q, want %q", i, e.Name, want)
			}
			if len(e.Data) == 0 {
				t.Fatalf("event %d data empty", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("event %d not delivered", i)
		}
	}
	cancel()
	<-done
}

func TestStreamHandlesCommentLines(t *testing.T) {
	out := make(chan Event, 1)
	r := stringReader(":keepalive\n\nevent: hello\ndata: \"x\"\n\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = parseSSE(ctx, r, out)
	}()
	select {
	case e := <-out:
		if e.Name != "hello" {
			t.Fatalf("name = %q", e.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("event not delivered")
	}
}

type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	n := copy(p, s)
	return n, nil
}
