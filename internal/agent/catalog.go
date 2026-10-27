package agent

import (
	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/workflow"
)

// catalogView projects a workflow into the catalog payload sent to the
// backend. Execution body (step.run, env values, working-directory,
// shell, secret.scope, output.from) is omitted.
func catalogView(w workflow.Workflow) apiclient.ReportedWorkflow {
	return apiclient.ReportedWorkflow{
		Name:          w.Name,
		Description:   w.Description,
		Version:       w.Version,
		SchemaVersion: w.SchemaVersion,
		VerboseSteps:  w.VerboseSteps(),
		SecretsKeys:   w.SecretNames(),
		Secrets:       reportedSecrets(w.Secrets),
		Params:        reportedParams(w.Params),
		Outputs:       reportedOutputs(w.Outputs),
		Retry:         reportedRetry(w.Retry),
		Steps:         reportedSteps(w.Steps),
		On:            reportedOn(w.On),
	}
}

func reportedOn(in *workflow.On) *apiclient.ReportedOn {
	if in == nil || in.Webhook == nil {
		return nil
	}
	webhook := &apiclient.ReportedOnWebhook{Refs: in.Webhook.Refs}
	if in.Webhook.Approval != nil {
		webhook.Approval = &apiclient.ReportedApproval{Methods: append([]string(nil), in.Webhook.Approval.Methods...)}
	}
	return &apiclient.ReportedOn{Webhook: webhook}
}

func reportedParams(in []workflow.Param) []apiclient.ReportedParam {
	if len(in) == 0 {
		return nil
	}
	out := make([]apiclient.ReportedParam, len(in))
	for i, p := range in {
		out[i] = apiclient.ReportedParam{
			Name:        p.Name,
			Type:        string(p.Type),
			Required:    p.Required,
			Description: p.Description,
			Default:     p.Default,
			Pattern:     p.Pattern,
			Options:     p.Options,
			Min:         p.Min,
			Max:         p.Max,
		}
	}
	return out
}

func reportedOutputs(in []workflow.Output) []apiclient.ReportedOutput {
	if len(in) == 0 {
		return nil
	}
	out := make([]apiclient.ReportedOutput, len(in))
	for i, o := range in {
		out[i] = apiclient.ReportedOutput{
			Name:        o.Name,
			Type:        string(o.Type),
			Description: o.Description,
		}
	}
	return out
}

func reportedSecrets(in []workflow.Secret) []apiclient.ReportedSecret {
	if len(in) == 0 {
		return nil
	}
	out := make([]apiclient.ReportedSecret, len(in))
	for i, s := range in {
		out[i] = apiclient.ReportedSecret{
			Name:        s.Name,
			Required:    s.Required,
			Description: s.Description,
		}
	}
	return out
}

func reportedRetry(in *workflow.Retry) *apiclient.ReportedRetry {
	if in == nil {
		return nil
	}
	return &apiclient.ReportedRetry{
		MaxAttempts:         in.MaxAttempts,
		Backoff:             string(in.Backoff),
		InitialDelaySeconds: in.InitialDelaySeconds,
		MaxDelaySeconds:     in.MaxDelaySeconds,
	}
}

func reportedSteps(in []workflow.Step) []apiclient.ReportedStep {
	if len(in) == 0 {
		return nil
	}
	out := make([]apiclient.ReportedStep, len(in))
	for i, s := range in {
		out[i] = apiclient.ReportedStep{
			ID:              s.ID,
			Name:            s.Name,
			TimeoutMinutes:  s.TimeoutMinutes,
			Verbose:         s.Verbose,
			ContinueOnError: s.ContinueOnError,
			Retry:           reportedRetry(s.Retry),
		}
	}
	return out
}
