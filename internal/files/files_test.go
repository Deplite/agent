package files

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
)

type stubSigner struct {
	id  string
	pri ed25519.PrivateKey
}

func (s stubSigner) AgentID() string      { return s.id }
func (s stubSigner) Sign(m []byte) []byte { return ed25519.Sign(s.pri, m) }

func newStubSigner(t *testing.T) stubSigner {
	t.Helper()
	_, pri, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return stubSigner{id: "a1", pri: pri}
}

// A presigned artifact URL can expire while the job waits in the local
// queue; a non-2xx download must trigger one refresh + retry.
func TestDownloadRefreshesOnStaleURL(t *testing.T) {
	const payload = "ARTIFACT-BYTES"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/blob":
			if r.URL.Query().Get("v") == "fresh" {
				_, _ = w.Write([]byte(payload))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "/download-url"):
			w.Header().Set("Content-Type", "application/json")
			fresh := "http://" + r.Host + "/blob?v=fresh"
			_, _ = fmt.Fprintf(w, `{"downloadUrl":%q,"expiresInSeconds":900}`, fresh)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := apiclient.New(srv.URL)
	dir := t.TempDir()
	r := NewResolver(c, newStubSigner(t), dir)

	ref := SerializedFileRef{ID: "f1", DownloadURL: srv.URL + "/blob?v=old"}
	dst, err := r.download(context.Background(), ref)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("content = %q, want %q", got, payload)
	}
}
