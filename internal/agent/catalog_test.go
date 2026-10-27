package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/workflow"
)

// The backend reads an absent `on` and an absent `refs` as two different
// things — no outside call at all, versus any ref — so the catalog has to
// keep emitting exactly these shapes.
func TestCatalogViewOnShape(t *testing.T) {
	cases := []struct {
		name string
		on   *workflow.On
		want string
	}{
		{"no on block", nil, ""},
		{"trigger the agent cannot act on", &workflow.On{}, ""},
		{"any ref", &workflow.On{Webhook: &workflow.OnWebhook{}}, `"on":{"webhook":{}}`},
		{"declared refs", &workflow.On{Webhook: &workflow.OnWebhook{Refs: []string{"main"}}}, `"on":{"webhook":{"refs":["main"]}}`},
	}
	for _, c := range cases {
		body, err := json.Marshal(catalogView(workflow.Workflow{Name: "deploy", On: c.on}))
		if err != nil {
			t.Fatalf("%s: marshal: %v", c.name, err)
		}
		got := string(body)
		if c.want == "" {
			if strings.Contains(got, `"on"`) {
				t.Errorf("%s: %s should not carry an on key", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %s does not contain %s", c.name, got, c.want)
		}
	}
}

func TestCatalogApprovalContainsOnlyMethods(t *testing.T) {
	wf := workflow.Workflow{
		Name: "deploy",
		On: &workflow.On{Webhook: &workflow.OnWebhook{
			Approval: &workflow.WebhookApproval{
				TOTP:    &workflow.TOTPApproval{SecretFile: "/private/totp"},
				Methods: []string{"hmac", "signature"},
			},
		}},
	}
	body, err := json.Marshal(catalogView(wf))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, `"approval":{"methods":["hmac","signature"]}`) {
		t.Fatalf("approval method report missing: %s", got)
	}
	if strings.Contains(got, "/private/totp") || strings.Contains(got, "secret-file") {
		t.Fatalf("local approval config leaked: %s", got)
	}
}
