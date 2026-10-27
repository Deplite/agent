package agent

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/joblog"
	"github.com/Deplite/agent/internal/mask"
	"github.com/Deplite/agent/internal/runner"
	"github.com/Deplite/agent/internal/textutil"
	"github.com/Deplite/agent/internal/workflow"
)

const maskedValue = "****"

// LoadWorkflow returns the workflow named name from dir. The error lists
// the names that are available so a typo is obvious.
func LoadWorkflow(dir, name string) (workflow.Workflow, error) {
	wfs, bad := workflow.Scan(dir)
	for i := range wfs {
		if wfs[i].Name == name {
			return wfs[i], nil
		}
	}
	names := make([]string, 0, len(wfs))
	for _, w := range wfs {
		names = append(names, w.Name)
	}
	if len(names) == 0 {
		if len(bad) > 0 {
			return workflow.Workflow{}, fmt.Errorf("%s 안의 워크플로우 파일이 모두 읽히지 않았습니다 (%d개 실패)", dir, len(bad))
		}
		return workflow.Workflow{}, fmt.Errorf("%s 에 워크플로우가 없습니다", dir)
	}
	return workflow.Workflow{}, fmt.Errorf("워크플로우 %q 를 찾을 수 없습니다. 사용 가능: %s", name, strings.Join(names, ", "))
}

// CoerceParams converts flag values, which always arrive as text, into
// the types the workflow declares. Values for undeclared names pass
// through untouched so ResolveParams stays the one place that rejects
// them.
func CoerceParams(wf workflow.Workflow, raw map[string]string) map[string]any {
	declared := make(map[string]workflow.ParamType, len(wf.Params))
	for _, p := range wf.Params {
		declared[p.Name] = p.Type
	}
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		switch declared[k] {
		case workflow.ParamNumber:
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				out[k] = n
				continue
			}
		case workflow.ParamBoolean:
			if b, err := strconv.ParseBool(v); err == nil {
				out[k] = b
				continue
			}
		}
		out[k] = v
	}
	return out
}

// LocalSecrets binds each declared secret from DEPLITE_SECRET_*, then
// applies the explicit overrides a local run passed on the command line.
func LocalSecrets(wf workflow.Workflow, override map[string]string) map[string]string {
	out := resolveSecrets(wf.Secrets)
	if out == nil {
		out = map[string]string{}
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

// DryRun writes the plan a real run would follow: what the params resolve
// to, which secrets are bound, and what each step would execute under.
func DryRun(wf workflow.Workflow, supplied map[string]any, secrets map[string]string, out io.Writer) error {
	resolved, err := wf.ResolveParams(supplied)
	if err != nil {
		return err
	}
	masked := wf.MaskedParams()

	fmt.Fprintf(out, "워크플로우: %s\n", wf.Name)
	if wf.Description != "" {
		fmt.Fprintf(out, "설명: %s\n", wf.Description)
	}
	if wf.Version != "" {
		fmt.Fprintf(out, "버전: %s\n", wf.Version)
	}
	fmt.Fprintf(out, "기본 셸: %s\n", runner.DefaultShell())
	if methods := wf.ApprovalMethods(); len(methods) > 0 {
		fmt.Fprintf(out, "외부 실행 승인: %s (로컬 실행에는 적용되지 않습니다)\n", strings.Join(methods, ", "))
	}

	fmt.Fprintf(out, "\n파라미터 (%d)\n", len(wf.Params))
	var params textutil.Table
	for _, p := range wf.Params {
		v, ok := resolved[p.Name]
		shown := "(값 없음)"
		switch {
		case masked[p.Name] && ok:
			shown = maskedValue
		case ok:
			shown = fmt.Sprintf("%v", v)
		}
		flags := []string{string(p.Type)}
		if p.Required {
			flags = append(flags, "필수")
		}
		if _, given := supplied[p.Name]; !given && ok {
			flags = append(flags, "기본값")
		}
		params.Add(p.Name, shown, "["+strings.Join(flags, ", ")+"]")
	}
	params.RenderIndent(out, "  ")

	fmt.Fprintf(out, "\n시크릿 (%d)\n", len(wf.Secrets))
	var secretRows textutil.Table
	for _, sec := range wf.Secrets {
		note := "미바인딩"
		if _, ok := secrets[sec.Name]; ok {
			note = "바인딩됨"
		} else if !sec.Required {
			note = "미바인딩 (선택)"
		}
		scope := "모든 스텝"
		if len(sec.Scope) > 0 {
			scope = "스텝 " + strings.Join(sec.Scope, ", ")
		}
		secretRows.Add(sec.Name, note, "["+scope+"]")
	}
	secretRows.RenderIndent(out, "  ")

	fmt.Fprintf(out, "\n스텝 (%d)\n", len(wf.Steps))
	for i, st := range wf.Steps {
		label := st.Name
		if st.ID != "" {
			label = fmt.Sprintf("%s (id: %s)", st.Name, st.ID)
		}
		fmt.Fprintf(out, "  %d. %s\n", i+1, label)
		fmt.Fprintf(out, "     셸=%s 타임아웃=%s\n", shellOf(st), stepTimeout(st))
		if st.WorkingDirectory != "" {
			fmt.Fprintf(out, "     working-directory=%s\n", st.WorkingDirectory)
		}
		if r := effectiveRetryOf(wf, st); r != nil {
			fmt.Fprintf(out, "     retry=%d회 backoff=%s\n", r.MaxAttempts, backoffName(r))
		}
		if st.ContinueOnError {
			fmt.Fprintln(out, "     continue-on-error=true")
		}
	}

	fmt.Fprintf(out, "\n스텝에 주입되는 환경변수 키\n  %s\n", strings.Join(injectedEnvKeys(wf, resolved, secrets), ", "))

	if err := runner.RequireSecrets(wf, secrets); err != nil {
		return err
	}
	fmt.Fprintln(out, "\n--dry-run 이므로 스텝은 실행하지 않았습니다.")
	return nil
}

// LocalRunOptions configures a run that never contacts the backend.
type LocalRunOptions struct {
	// DataDir, when set, is where the run mirrors its log files so
	// `deplite-agent logs` can replay it. Empty disables the mirror.
	DataDir string
	Debug   bool
	Out     io.Writer
}

// RunLocal executes wf on this machine. Nothing is reported to the
// backend: logs are echoed to opts.Out and, when DataDir is set,
// mirrored to the same place a backend-dispatched job writes them.
func RunLocal(ctx context.Context, wf workflow.Workflow, params map[string]any, secrets map[string]string, opts LocalRunOptions) runner.Result {
	jobID := "local-" + time.Now().UTC().Format("20060102-150405")
	if opts.DataDir != "" {
		joblog.LocalDir = resolveLogDir(opts.DataDir)
	} else {
		joblog.LocalDir = ""
	}

	shipper := joblog.New(discardSink{}, nil)
	shipper.SetEcho(func(stream apiclient.LogStream, stepName, content string) {
		switch {
		case stream == apiclient.LogStreamSystem && stepName != "":
			fmt.Fprintf(opts.Out, "[%s] %s\n", stepName, content)
		case stream == apiclient.LogStreamSystem:
			fmt.Fprintf(opts.Out, "[deplite] %s\n", content)
		default:
			fmt.Fprintln(opts.Out, content)
		}
	})
	defer shipper.Forget(jobID)

	fmt.Fprintf(opts.Out, "[deplite] job %s\n", jobID)
	result := runner.Run(ctx, wf, jobID, params, secrets, shipper, mask.New(), opts.Debug)
	if len(result.Outputs) > 0 {
		fmt.Fprintln(opts.Out, "\n출력")
		var outputs textutil.Table
		for _, k := range sortedKeys(result.Outputs) {
			outputs.Add(k, fmt.Sprintf("%v", result.Outputs[k]))
		}
		outputs.RenderIndent(opts.Out, "  ")
	}
	return result
}

// discardSink stands in for the backend so a local run keeps the same
// shipper plumbing without sending anything.
type discardSink struct{}

func (discardSink) AppendJobLogs(context.Context, apiclient.Signer, string, []apiclient.LogItem) (apiclient.LogsResponse, error) {
	return apiclient.LogsResponse{}, nil
}

func shellOf(st workflow.Step) string {
	if st.Shell != "" {
		return st.Shell
	}
	return runner.DefaultShell()
}

func stepTimeout(st workflow.Step) string {
	if st.TimeoutMinutes > 0 {
		return fmt.Sprintf("%d분", st.TimeoutMinutes)
	}
	return "30분(기본값)"
}

func effectiveRetryOf(wf workflow.Workflow, st workflow.Step) *workflow.Retry {
	if st.Retry != nil {
		return st.Retry
	}
	return wf.Retry
}

func backoffName(r *workflow.Retry) string {
	if r.Backoff == "" {
		return "fixed"
	}
	return string(r.Backoff)
}

// injectedEnvKeys lists the DEPLITE_* and workflow-declared keys a step
// receives, so a dry run shows what the script can read without printing
// any value.
func injectedEnvKeys(wf workflow.Workflow, params map[string]any, secrets map[string]string) []string {
	keys := []string{"DEPLITE_WORKDIR", "TMPDIR", "TMP"}
	for _, st := range wf.Steps {
		if st.ID != "" {
			keys = append(keys, "DEPLITE_OUTPUT")
			break
		}
	}
	seen := map[string]bool{}
	for _, st := range wf.Steps {
		for k := range st.Env {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	for k := range wf.Env {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, k := range sortedKeys(params) {
		keys = append(keys, "DEPLITE_PARAM_"+runner.EnvName(k))
	}
	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		keys = append(keys, "DEPLITE_SECRET_"+runner.EnvName(k))
	}
	return keys
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseKeyValues turns repeated "key=value" flags into a map.
func ParseKeyValues(pairs []string, flagName string) (map[string]string, error) {
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s 는 key=value 형식이어야 합니다: %q", flagName, p)
		}
		out[k] = v
	}
	return out, nil
}

// ResolveLogDir exposes where job logs are mirrored for this data dir.
func ResolveLogDir(dataDir string) string { return resolveLogDir(dataDir) }
