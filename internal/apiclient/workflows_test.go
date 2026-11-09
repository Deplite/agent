package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestReportWorkflowsAlwaysSendsInvalidArray(t *testing.T) {
	var body reportRequest
	client := testReportClient(func(r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
	})

	if _, err := client.ReportWorkflows(context.Background(), newFakeSigner(t, "agent"), nil, nil); err != nil {
		t.Fatal(err)
	}
	if body.Workflows == nil || body.Invalid == nil {
		t.Fatalf("empty arrays decoded nil: workflows=%v invalid=%v", body.Workflows, body.Invalid)
	}
	if len(body.Workflows) != 0 || len(body.Invalid) != 0 {
		t.Fatalf("empty report = %+v", body)
	}
}

func TestReportWorkflowsConstrainsInvalidEntries(t *testing.T) {
	var body reportRequest
	client := testReportClient(func(r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
	})

	invalid := make([]InvalidWorkflow, 0, 101)
	for i := 100; i >= 0; i-- {
		name := "wf-" + string([]byte{byte('0' + i/100), byte('0' + i/10%10), byte('0' + i%10)})
		item := InvalidWorkflow{Name: name, Code: "duplicate_name", Reason: strings.Repeat("한", 501)}
		if i == 0 {
			item.Reason = strings.Repeat("한", 498) + "😀Z"
			item.Files = []string{"", strings.Repeat("a", 254) + "😀", strings.Repeat("한", 253) + "😀"}
			for j := 0; j < 21; j++ {
				item.Files = append(item.Files, "path-"+string([]byte{byte('0' + j/10), byte('0' + j%10)}))
			}
		}
		invalid = append(invalid, item)
	}
	if _, err := client.ReportWorkflows(context.Background(), newFakeSigner(t, "agent"), nil, invalid); err != nil {
		t.Fatal(err)
	}
	if len(body.Invalid) != 100 {
		t.Fatalf("invalid entries = %d, want 100", len(body.Invalid))
	}
	if body.Invalid[0].Name != "wf-000" || body.Invalid[99].Name != "wf-099" {
		t.Fatalf("invalid name bounds = %q..%q", body.Invalid[0].Name, body.Invalid[99].Name)
	}
	wantReason := strings.Repeat("한", 498) + "😀"
	if got := utf16Length(body.Invalid[0].Reason); got != 500 || body.Invalid[0].Reason != wantReason {
		t.Fatalf("reason = %q (%d UTF-16 units), want %q", body.Invalid[0].Reason, got, wantReason)
	}
	if len(body.Invalid[0].Files) != 20 {
		t.Fatalf("files = %d, want 20", len(body.Invalid[0].Files))
	}
	wantBoundaryPath := strings.Repeat("한", 253) + "😀"
	if body.Invalid[0].Files[0] != wantBoundaryPath || body.Invalid[0].Files[19] != "path-18" {
		t.Fatalf("files boundary = %q..%q", body.Invalid[0].Files[0], body.Invalid[0].Files[19])
	}
	for _, path := range body.Invalid[0].Files {
		if units := utf16Length(path); units < 1 || units > 255 {
			t.Fatalf("invalid path length was included: %d UTF-16 units", units)
		}
	}
	if body.Invalid[1].Files == nil || len(body.Invalid[1].Files) != 0 {
		t.Fatalf("empty files field = %#v, want []", body.Invalid[1].Files)
	}
}

func utf16Length(value string) int { return len(utf16.Encode([]rune(value))) }

func TestNormalizeInvalidWorkflowEnforcesUTF16FieldBounds(t *testing.T) {
	valid := InvalidWorkflow{
		Name:   strings.Repeat("😀", 64),
		Code:   strings.Repeat("😀", 32),
		Reason: "r",
		Files:  []string{"", strings.Repeat("😀", 128), strings.Repeat("😀", 127)},
	}
	got := normalizeInvalidWorkflows([]InvalidWorkflow{
		valid,
		{Name: strings.Repeat("😀", 65), Code: "duplicate_name", Reason: "reason"},
		{Name: "bad-code", Code: strings.Repeat("😀", 33), Reason: "reason"},
		{Name: "bad-reason", Code: "duplicate_name"},
	})
	if len(got) != 1 || got[0].Name != valid.Name || got[0].Code != valid.Code {
		t.Fatalf("normalized entries = %+v", got)
	}
	if len(got[0].Files) != 1 || got[0].Files[0] != strings.Repeat("😀", 127) {
		t.Fatalf("normalized files = %#v", got[0].Files)
	}
}

type workflowsRoundTripper func(*http.Request)

func (f workflowsRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	f(r)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"count":0}`)),
		Request:    r,
	}, nil
}

func testReportClient(capture func(*http.Request)) *Client {
	client := New("http://backend.test")
	client.HTTPClient = &http.Client{Transport: workflowsRoundTripper(capture)}
	return client
}
