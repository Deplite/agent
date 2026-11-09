package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
)

func TestUpdateIdentityRequestSeesExistingRunState(t *testing.T) {
	dataDir := t.TempDir()
	client := apiclient.New("https://agent.test")
	var requestErr error
	called := false
	client.HTTPClient = &http.Client{Transport: identityRoundTripper(func(*http.Request) (*http.Response, error) {
		called = true
		state, err := ReadRunState(dataDir)
		if err != nil {
			requestErr = err
			return nil, errors.New("run state was not written before identity request")
		}
		if state.PID != os.Getpid() || state.Version != "0.2.0" {
			requestErr = errors.New("run state has unexpected PID or version")
			return nil, requestErr
		}
		return nil, errors.New("backend unavailable")
	})}
	state := newStateWriter(dataDir, "0.2.0")
	defer state.remove()
	updateIdentity(context.Background(), client, identityTestSigner{}, apiclient.IdentityPatch{AgentVersion: "0.2.0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !called {
		t.Fatal("identity request was not attempted")
	}
	if requestErr != nil {
		t.Fatalf("state at identity request: %v", requestErr)
	}
}

type identityRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip identityRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type identityTestSigner struct{}

func (identityTestSigner) AgentID() string    { return "test-agent" }
func (identityTestSigner) Sign([]byte) []byte { return []byte("test-signature") }
