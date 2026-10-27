package workflow

import "strings"

// StepOutputs maps step id → key → captured value.
type StepOutputs map[string]map[string]string

// ResolveOutputs projects per-step captured outputs into the
// workflow-level output map declared in w.Outputs. Missing references
// resolve to empty string.
func (w Workflow) ResolveOutputs(captured StepOutputs) map[string]string {
	out := make(map[string]string, len(w.Outputs))
	for _, o := range w.Outputs {
		parts := strings.SplitN(o.From, ".", 2)
		if len(parts) != 2 {
			continue
		}
		stepID, key := parts[0], parts[1]
		if perStep, ok := captured[stepID]; ok {
			out[o.Name] = perStep[key]
		}
	}
	return out
}
