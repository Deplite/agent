//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/signing"
)

const timestampSkew = 300

// mockBackend is a self-contained stand-in for the Deplite backend. It
// re-implements the wire protocol from scratch (Bearer enroll, Ed25519
// request signatures over "ts\nnonce\nMETHOD\npath\nsha256_hex(body)",
// signed deploy envelopes) so the agent's implementation is verified
// against an independent one, not against itself.
type mockBackend struct {
	t           *testing.T
	server      *httptest.Server
	installCode string

	serverPub  ed25519.PublicKey
	serverPriv ed25519.PrivateKey

	mu             sync.Mutex
	codeUsed       bool
	agentID        string
	agentPub       ed25519.PublicKey
	enrolls        int
	enrollName     string
	heartbeats     int
	probeID        string
	probeAcks      []string
	streamFeatures []string
	identity       int
	desiredCalls   int
	reportRaw      []string
	nonces         map[string]bool
	logs           map[string][]logItem
	results        map[string][]jobResultBody
	authFailures   []string
	deployOnce     sync.Once
	deployEvents   []string
	blobs          map[string][]byte
}

type logItem struct {
	Seq      int     `json:"seq"`
	Stream   string  `json:"stream"`
	StepName *string `json:"stepName,omitempty"`
	Level    string  `json:"level,omitempty"`
	Content  string  `json:"content"`
}

type jobResultBody struct {
	Status         string         `json:"status"`
	ExitCode       *int           `json:"exitCode"`
	ErrorMessage   string         `json:"errorMessage"`
	Reason         string         `json:"reason"`
	Output         map[string]any `json:"output"`
	BypassedLimits []string       `json:"bypassedLimits"`
}

func newMockBackend(t *testing.T, installCode string) *mockBackend {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	m := &mockBackend{
		t:           t,
		installCode: installCode,
		serverPub:   pub,
		serverPriv:  priv,
		agentID:     "agt_e2e_1",
		nonces:      map[string]bool{},
		logs:        map[string][]logItem{},
		results:     map[string][]jobResultBody{},
		blobs:       map[string][]byte{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/enroll", m.handleEnroll)
	mux.HandleFunc("PATCH /v1/agent/identity", m.signed(m.handleIdentity))
	mux.HandleFunc("POST /v1/agent/heartbeat", m.signed(m.handleHeartbeat))
	mux.HandleFunc("POST /v1/agent/workflows/report", m.signed(m.handleWorkflowsReport))
	mux.HandleFunc("GET /v1/agent/stream", m.handleStream)
	mux.HandleFunc("GET /v1/agent/deploy/desired", m.signed(m.handleDesired))
	mux.HandleFunc("POST /v1/agent/deploy/report", m.signed(m.handleDeviceReport))
	mux.HandleFunc("GET /v1/agent/files/{id}/blob", m.handleFileBlob)
	mux.HandleFunc("POST /v1/agent/jobs/{id}/logs", m.signed(m.handleJobLogs))
	mux.HandleFunc("POST /v1/agent/jobs/{id}/result", m.signed(m.handleJobResult))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock: unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(func() {
		m.server.CloseClientConnections()
		m.server.Close()
	})
	return m
}

func (m *mockBackend) baseURL() string { return m.server.URL + "/v1" }

func (m *mockBackend) serverPublicKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(m.serverPub)
	if err != nil {
		m.t.Fatalf("marshal server public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (m *mockBackend) handleEnroll(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+m.installCode {
		http.Error(w, `{"error":"invalid install code"}`, http.StatusUnauthorized)
		return
	}
	if m.codeUsed {
		http.Error(w, `{"error":"install code already used"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		Name      string `json:"name"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.PublicKey == "" {
		http.Error(w, `{"error":"bad enroll body"}`, http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.PublicKey))
	if block == nil {
		http.Error(w, `{"error":"publicKey is not PEM"}`, http.StatusBadRequest)
		return
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		http.Error(w, `{"error":"publicKey parse failed"}`, http.StatusBadRequest)
		return
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		http.Error(w, `{"error":"publicKey is not ed25519"}`, http.StatusBadRequest)
		return
	}

	m.codeUsed = true
	m.agentPub = pub
	m.enrolls++
	m.enrollName = body.Name
	writeJSON(w, map[string]string{
		"agentId":         m.agentID,
		"organizationId":  "org_e2e",
		"serverPublicKey": m.serverPublicKeyPEM(),
	})
}

// signed wraps a handler with the Ed25519 request-signature check every
// non-enroll endpoint requires.
func (m *mockBackend) signed(next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
			return
		}
		if msg, ok := m.verifySignature(r, body); !ok {
			m.mu.Lock()
			m.authFailures = append(m.authFailures, fmt.Sprintf("%s %s: %s", r.Method, r.URL.Path, msg))
			m.mu.Unlock()
			http.Error(w, `{"error":"`+msg+`"}`, http.StatusUnauthorized)
			return
		}
		next(w, r, body)
	}
}

func (m *mockBackend) verifySignature(r *http.Request, body []byte) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.agentPub == nil {
		return "agent not enrolled", false
	}
	if got := r.Header.Get("x-agent-id"); got != m.agentID {
		return "unknown agent id " + got, false
	}
	ts := r.Header.Get("x-timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "bad timestamp", false
	}
	if d := time.Now().Unix() - sec; d > timestampSkew || d < -timestampSkew {
		return "timestamp outside skew", false
	}
	nonce := r.Header.Get("x-nonce")
	if nonce == "" {
		return "missing nonce", false
	}
	if m.nonces[nonce] {
		return "nonce replayed", false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("x-signature"))
	if err != nil {
		return "signature not base64", false
	}
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{
		ts, nonce, r.Method, r.URL.Path, hex.EncodeToString(digest[:]),
	}, "\n")
	if !ed25519.Verify(m.agentPub, []byte(canonical), sig) {
		return "signature verification failed", false
	}
	m.nonces[nonce] = true
	return "", true
}

func (m *mockBackend) handleIdentity(w http.ResponseWriter, _ *http.Request, _ []byte) {
	m.mu.Lock()
	m.identity++
	m.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}

func (m *mockBackend) handleHeartbeat(w http.ResponseWriter, _ *http.Request, body []byte) {
	var req struct {
		ProbeID string `json:"probeId"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"bad heartbeat body"}`, http.StatusBadRequest)
			return
		}
	}
	m.mu.Lock()
	m.heartbeats++
	if req.ProbeID != "" {
		m.probeAcks = append(m.probeAcks, req.ProbeID)
	}
	m.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}

func (m *mockBackend) handleWorkflowsReport(w http.ResponseWriter, _ *http.Request, body []byte) {
	var req struct {
		Workflows []json.RawMessage `json:"workflows"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"bad report body"}`, http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.reportRaw = append(m.reportRaw, string(body))
	m.mu.Unlock()
	writeJSON(w, map[string]int{"count": len(req.Workflows)})
}

func (m *mockBackend) handleDesired(w http.ResponseWriter, _ *http.Request, _ []byte) {
	m.mu.Lock()
	m.desiredCalls++
	m.mu.Unlock()
	writeJSON(w, map[string]any{"apps": []any{}})
}

func (m *mockBackend) handleDeviceReport(w http.ResponseWriter, _ *http.Request, _ []byte) {
	writeJSON(w, map[string]bool{"ok": true})
}

func (m *mockBackend) handleJobLogs(w http.ResponseWriter, r *http.Request, body []byte) {
	var req struct {
		Items []logItem `json:"items"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"bad logs body"}`, http.StatusBadRequest)
		return
	}
	jobID := r.PathValue("id")
	m.mu.Lock()
	m.logs[jobID] = append(m.logs[jobID], req.Items...)
	m.mu.Unlock()
	writeJSON(w, map[string]int{"accepted": len(req.Items)})
}

func (m *mockBackend) handleJobResult(w http.ResponseWriter, r *http.Request, body []byte) {
	var res jobResultBody
	if err := json.Unmarshal(body, &res); err != nil {
		http.Error(w, `{"error":"bad result body"}`, http.StatusBadRequest)
		return
	}
	jobID := r.PathValue("id")
	m.mu.Lock()
	m.results[jobID] = append(m.results[jobID], res)
	m.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "status": res.Status})
}

func (m *mockBackend) handleStream(w http.ResponseWriter, r *http.Request) {
	if msg, ok := m.verifySignature(r, nil); !ok {
		m.mu.Lock()
		m.authFailures = append(m.authFailures, "GET /v1/agent/stream: "+msg)
		m.mu.Unlock()
		http.Error(w, `{"error":"`+msg+`"}`, http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	features := r.Header.Get("x-deplite-features")
	m.mu.Lock()
	m.streamFeatures = append(m.streamFeatures, features)
	probeID := m.probeID
	m.mu.Unlock()
	if features == "probe" && probeID != "" {
		fmt.Fprintf(w, "event: probe\ndata: {\"probe_id\":%q}\n\n", probeID)
		flusher.Flush()
	}

	m.deployOnce.Do(func() {
		for _, ev := range m.deployEvents {
			fmt.Fprintf(w, "event: deploy\ndata: %s\n\n", ev)
			flusher.Flush()
		}
	})

	<-r.Context().Done()
}

// deployPayloadFields is canonicalized as a complete payload before signing.
type deployPayloadFields struct {
	Approval     json.RawMessage `json:"approval,omitempty"`
	Debug        bool            `json:"debug"`
	IssuedAt     int64           `json:"issued_at"`
	JobID        string          `json:"job_id"`
	Nonce        string          `json:"nonce"`
	Params       map[string]any  `json:"params"`
	WorkflowName string          `json:"workflow_name"`
}

// prepareDeploy queues a signed envelope for handleStream to emit on the
// first stream connection.
func (m *mockBackend) prepareDeploy(jobID, workflowName string, params map[string]any, debug bool) {
	m.prepareDeployWithApproval(jobID, workflowName, params, debug, nil)
}

func (m *mockBackend) prepareDeployWithApproval(jobID, workflowName string, params map[string]any, debug bool, approval json.RawMessage) {
	payload, err := signing.CanonicalJSON(deployPayloadFields{
		Approval:     approval,
		Debug:        debug,
		IssuedAt:     time.Now().Unix(),
		JobID:        jobID,
		Nonce:        "dp-" + jobID,
		Params:       params,
		WorkflowName: workflowName,
	})
	if err != nil {
		m.t.Fatalf("canonicalize deploy payload: %v", err)
	}
	sig := ed25519.Sign(m.serverPriv, payload)
	envelope, err := json.Marshal(map[string]any{
		"payload":   json.RawMessage(payload),
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		m.t.Fatalf("marshal deploy envelope: %v", err)
	}
	m.deployEvents = append(m.deployEvents, string(envelope))
}

// serveBlob registers an artifact download and returns the FileRef param the
// backend would put in an OTA job.
func (m *mockBackend) serveBlob(id string, data []byte) map[string]any {
	m.mu.Lock()
	m.blobs[id] = data
	m.mu.Unlock()
	return map[string]any{
		"__type":      "FileRef",
		"id":          id,
		"filename":    id + ".bin",
		"contentType": "application/octet-stream",
		"size":        float64(len(data)),
		"downloadUrl": m.baseURL() + "/agent/files/" + id + "/blob",
	}
}

func (m *mockBackend) handleFileBlob(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	data, ok := m.blobs[r.PathValue("id")]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (m *mockBackend) jobResults(jobID string) []jobResultBody {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]jobResultBody, len(m.results[jobID]))
	copy(out, m.results[jobID])
	return out
}

func (m *mockBackend) jobLogContents(jobID, stream string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, it := range m.logs[jobID] {
		if it.Stream == stream {
			out = append(out, it.Content)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
