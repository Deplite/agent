package agent

import (
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/workflow"
)

func TestCallDenied(t *testing.T) {
	closed := &workflow.Workflow{Name: "deploy"}
	anyRef := &workflow.Workflow{Name: "deploy", On: &workflow.On{Webhook: &workflow.OnWebhook{}}}
	mainOnly := &workflow.Workflow{Name: "deploy", On: &workflow.On{Webhook: &workflow.OnWebhook{Refs: []string{"main"}}}}

	cases := []struct {
		name    string
		wf      *workflow.Workflow
		payload apiclient.DeployPayload
		want    string
	}{
		{"legacy trigger on a workflow without on:", closed, apiclient.DeployPayload{}, ""},
		{"legacy trigger ignores refs", mainOnly, apiclient.DeployPayload{Ref: "topic"}, ""},
		{"run without on:", closed, apiclient.DeployPayload{Via: apiclient.ViaRun}, "on.webhook"},
		{"run with any ref allowed", anyRef, apiclient.DeployPayload{Via: apiclient.ViaRun, Ref: "topic"}, ""},
		{"run on a declared ref", mainOnly, apiclient.DeployPayload{Via: apiclient.ViaRun, Ref: "main"}, ""},
		{"run on an undeclared ref", mainOnly, apiclient.DeployPayload{Via: apiclient.ViaRun, Ref: "topic"}, "outside the refs"},
		{"run with no ref", mainOnly, apiclient.DeployPayload{Via: apiclient.ViaRun}, "outside the refs"},
	}
	for _, c := range cases {
		got := callDenied(c.wf, c.payload)
		switch {
		case c.want == "" && got != "":
			t.Errorf("%s: rejected with %q, want allowed", c.name, got)
		case c.want != "" && !strings.Contains(got, c.want):
			t.Errorf("%s: got %q, want it to mention %q", c.name, got, c.want)
		}
	}
}
