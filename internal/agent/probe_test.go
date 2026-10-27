package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/signing"
)

func TestInvalidProbeEventsAreIgnored(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, data := range []json.RawMessage{nil, json.RawMessage(`{`), json.RawMessage(`{ "probe_id": "  " }`)} {
		jobs := make(chan apiclient.DeployPayload, 1)
		handleEvent(context.Background(), nil, nil, "", apiclient.Event{Name: "probe", Data: data}, jobs, "", nil, nil, nil, log)
		select {
		case job := <-jobs:
			t.Fatalf("invalid probe dispatched as job: %+v", job)
		default:
		}
	}
}

func TestProbeHeartbeatFailureDoesNotStopStreamLoop(t *testing.T) {
	probeFailures := make(chan string, 2)
	attempted := make(chan string, 2)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("stream response does not support flushing")
			return
		}
		for _, probeID := range []string{"probe-1", "probe-2"} {
			_, _ = w.Write([]byte("event: probe\ndata: {\"probe_id\":\"" + probeID + "\"}\n\n"))
			flusher.Flush()
			select {
			case got := <-probeFailures:
				if got != probeID {
					t.Errorf("failed probe = %q, want %q", got, probeID)
				}
			case <-r.Context().Done():
				return
			case <-time.After(3 * time.Second):
				t.Errorf("timed out waiting for failed heartbeat for %q", probeID)
				return
			}
		}
		<-r.Context().Done()
	})
	mux.HandleFunc("POST /v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProbeID string `json:"probeId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode probe heartbeat body: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		probeFailures <- body.ProbeID
		attempted <- body.ProbeID
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	signer := newSigner("agent-probe", kp)
	client := apiclient.New(srv.URL + "/v1")
	jobs := make(chan apiclient.DeployPayload, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan error, 1)
	go func() {
		done <- streamLoop(ctx, client, signer, "", jobs, "", nil, nil, nil, nil, log)
	}()

	for _, want := range []string{"probe-1", "probe-2"} {
		select {
		case got := <-attempted:
			if got != want {
				t.Fatalf("heartbeat probeId = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("heartbeat for %q was not attempted", want)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream loop returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream loop did not stop after cancellation")
	}
	select {
	case job := <-jobs:
		t.Fatalf("probe dispatched as job: %+v", job)
	default:
	}
}
