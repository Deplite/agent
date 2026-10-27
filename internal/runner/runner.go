// Package runner executes a workflow's steps.
package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/joblog"
	"github.com/Deplite/agent/internal/mask"
	"github.com/Deplite/agent/internal/workflow"
)

type Result struct {
	Status   apiclient.JobStatus
	ExitCode int
	Error    string
	Outputs  map[string]any
}

const defaultStepTimeout = 30 * time.Minute

// Run executes wf and returns the terminal job status.
func Run(
	ctx context.Context,
	wf workflow.Workflow,
	jobID string,
	params map[string]any,
	secretValues map[string]string,
	shipper *joblog.Shipper,
	masker *mask.Masker,
	debug bool,
) Result {
	masker.Reset()
	for _, v := range secretValues {
		masker.Add(v)
	}
	// Registered from the supplied params rather than the resolved ones: a
	// value can reach the log through a ResolveParams error below, before
	// resolution has happened.
	for name := range wf.MaskedParams() {
		if v, ok := params[name].(string); ok {
			masker.Add(v)
		}
	}

	logSys := func(stepName, msg string) {
		shipper.Append(jobID, apiclient.LogStreamSystem, stepName, masker.Apply(msg), apiclient.LogLevelInfo)
	}

	resolvedParams, err := wf.ResolveParams(params)
	if err != nil {
		logSys("", "param validation failed: "+err.Error())
		return Result{Status: apiclient.JobFailed, Error: "param validation: " + err.Error()}
	}
	if err := requireSecrets(wf, secretValues); err != nil {
		logSys("", err.Error())
		return Result{Status: apiclient.JobFailed, Error: err.Error()}
	}

	scratch, err := makeScratch(jobID)
	if err != nil {
		logSys("", "could not create scratch dir: "+err.Error())
		return Result{Status: apiclient.JobFailed, Error: "scratch dir: " + err.Error()}
	}
	defer os.RemoveAll(scratch)

	if wf.TimeoutMinutes > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(wf.TimeoutMinutes)*time.Minute)
		defer cancel()
	}

	logSys("", fmt.Sprintf("workflow=%s steps=%d", wf.Name, len(wf.Steps)))

	captured := workflow.StepOutputs{}
	var lastExitCode int

	for _, step := range wf.Steps {
		if err := ctx.Err(); err != nil {
			return classifyContextErr(err, "canceled")
		}

		stepRetry := effectiveRetry(wf.Retry, step.Retry)
		secretsForStep := filterSecretsForStep(wf.Secrets, secretValues, step.ID)

		exitCode, outputs, runErr := runStepWithRetry(
			ctx, wf, step, resolvedParams, secretsForStep, scratch, jobID, shipper, masker, stepRetry, logSys, debug,
		)
		lastExitCode = exitCode
		if step.ID != "" && outputs != nil {
			captured[step.ID] = outputs
		}

		if runErr != nil {
			if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				logSys(step.Name, "step timed out")
				if step.ContinueOnError {
					logSys(step.Name, "continue-on-error: ignoring timeout")
					continue
				}
				return Result{Status: apiclient.JobTimeout, ExitCode: exitCode, Error: "timeout: " + step.Name}
			}
			logSys(step.Name, "step error: "+runErr.Error())
			if step.ContinueOnError {
				logSys(step.Name, "continue-on-error: ignoring error")
				continue
			}
			return Result{Status: apiclient.JobFailed, ExitCode: exitCode, Error: runErr.Error()}
		}
		if exitCode != 0 {
			logSys(step.Name, fmt.Sprintf("step exited %d", exitCode))
			if step.ContinueOnError {
				logSys(step.Name, "continue-on-error: ignoring non-zero exit")
				continue
			}
			return Result{Status: apiclient.JobFailed, ExitCode: exitCode, Error: fmt.Sprintf("step %s exited %d", step.Name, exitCode)}
		}
	}

	finalOutputs := materializeOutputs(wf, captured)
	logSys("", "workflow complete")
	return Result{Status: apiclient.JobSuccess, ExitCode: lastExitCode, Outputs: finalOutputs}
}

func classifyContextErr(err error, fallback string) Result {
	if errors.Is(err, context.DeadlineExceeded) {
		return Result{Status: apiclient.JobTimeout, Error: "timeout"}
	}
	return Result{Status: apiclient.JobFailed, Error: fallback}
}

func runStepWithRetry(
	ctx context.Context,
	wf workflow.Workflow,
	step workflow.Step,
	params map[string]any,
	secrets map[string]string,
	scratch string,
	jobID string,
	shipper *joblog.Shipper,
	masker *mask.Masker,
	retry *workflow.Retry,
	logSys func(string, string),
	debug bool,
) (int, map[string]string, error) {
	attempts := 1
	if retry != nil && retry.MaxAttempts > 0 {
		attempts = retry.MaxAttempts
	}
	var (
		lastExit int
		lastErr  error
		lastOut  map[string]string
	)
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			delay := backoffDelay(retry, attempt)
			logSys(step.Name, fmt.Sprintf("retry %d/%d after %s", attempt-1, attempts-1, delay))
			select {
			case <-ctx.Done():
				return lastExit, lastOut, ctx.Err()
			case <-time.After(delay):
			}
		}
		exit, out, err := runStep(ctx, wf, step, params, secrets, scratch, jobID, shipper, masker, logSys, debug)
		lastExit, lastErr, lastOut = exit, err, out
		if err == nil && exit == 0 {
			return exit, out, nil
		}
		if errors.Is(err, context.Canceled) {
			return exit, out, err
		}
	}
	return lastExit, lastOut, lastErr
}

func runStep(
	ctx context.Context,
	wf workflow.Workflow,
	step workflow.Step,
	params map[string]any,
	secrets map[string]string,
	scratch string,
	jobID string,
	shipper *joblog.Shipper,
	masker *mask.Masker,
	logSys func(string, string),
	debug bool,
) (int, map[string]string, error) {
	timeout := time.Duration(step.TimeoutMinutes) * time.Minute
	if timeout <= 0 {
		timeout = defaultStepTimeout
	}
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	outputFile := ""
	if step.ID != "" {
		f, err := os.CreateTemp(scratch, "out-"+step.ID+"-*")
		if err != nil {
			return -1, nil, err
		}
		outputFile = f.Name()
		_ = f.Close()
	}

	workDir, err := expandHome(step.WorkingDirectory)
	if err != nil {
		return -1, nil, err
	}

	shell := resolveShell(step.Shell)
	cmd := exec.CommandContext(stepCtx, shell, "-c", step.Run)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Keep shell children from outliving a canceled step.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Env = buildEnv(params, secrets, scratch, outputFile, wf.Env, step.Env)
	if workDir != "" {
		cmd.Dir = workDir
	} else {
		cmd.Dir = scratch
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, nil, err
	}
	if err := cmd.Start(); err != nil {
		return -1, nil, err
	}

	// Raw stdout/stderr only leaves the host when the step opted into
	// verbose logging AND the job was triggered with debug enabled.
	// Otherwise it is mirrored locally and operators see only the
	// system stream.
	shipRaw := debug && step.Verbose

	done := make(chan struct{}, 2)
	go pumpLines(stdout, step.Name, jobID, shipper, masker, apiclient.LogLevelInfo, shipRaw, done)
	go pumpLines(stderr, step.Name, jobID, shipper, masker, apiclient.LogLevelError, shipRaw, done)
	<-done
	<-done

	waitErr := cmd.Wait()
	outputs := readOutputs(outputFile, masker)

	if waitErr != nil {
		logSys(step.Name, stepContext(shell, cmd.Dir, cmd.Env))
		if stepCtx.Err() == context.DeadlineExceeded {
			return -1, outputs, context.DeadlineExceeded
		}
		if ee, ok := waitErr.(*exec.ExitError); ok {
			return ee.ExitCode(), outputs, nil
		}
		return -1, outputs, waitErr
	}
	return 0, outputs, nil
}

// DefaultShell returns the shell a step runs under when it declares none.
func DefaultShell() string { return resolveShell("") }

func resolveShell(stepShell string) string {
	switch {
	case stepShell != "":
		return stepShell
	case os.Getenv("DEPLITE_SHELL") != "":
		return os.Getenv("DEPLITE_SHELL")
	default:
		return "/bin/sh"
	}
}

func pumpLines(r io.Reader, step, jobID string, shipper *joblog.Shipper, masker *mask.Masker, level apiclient.LogLevel, shipRaw bool, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := masker.Apply(scanner.Text())
		if shipRaw {
			shipper.Append(jobID, apiclient.LogStreamRaw, step, line, level)
		} else {
			shipper.MirrorRaw(jobID, line)
		}
	}
}

// Precedence (later overrides): host → PATH → workdir → workflow env →
// params → secrets → step env. Step env wins so authors can override
// anything; secrets sit above params so a leaked param can't shadow a
// declared secret.
func buildEnv(params map[string]any, secrets map[string]string, scratch, outputFile string, workflowEnv, stepEnv map[string]string) []string {
	env := os.Environ()
	env = append(env, "PATH="+stepPath(os.Getenv("PATH")))
	env = append(env, "DEPLITE_WORKDIR="+scratch)
	env = append(env, "TMPDIR="+scratch, "TMP="+scratch)
	if outputFile != "" {
		env = append(env, "DEPLITE_OUTPUT="+outputFile)
	}
	for k, v := range workflowEnv {
		env = append(env, k+"="+v)
	}
	for k, v := range params {
		env = append(env, fmt.Sprintf("DEPLITE_PARAM_%s=%v", upper(k), v))
	}
	for k, v := range secrets {
		env = append(env, fmt.Sprintf("DEPLITE_SECRET_%s=%s", upper(k), v))
	}
	for k, v := range stepEnv {
		env = append(env, k+"="+v)
	}
	return env
}

func upper(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "_")) }

// EnvName renders a param or secret name the way it appears in a step's
// environment, after the DEPLITE_PARAM_ / DEPLITE_SECRET_ prefix.
func EnvName(s string) string { return upper(s) }

// Appended so steps find standard tools with a minimal inherited PATH; systemd also lacks /snap/bin.
var extraPathDirs = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
	"/snap/bin",
}

func stepPath(current string) string {
	seen := make(map[string]bool)
	var dirs []string
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	for _, d := range filepath.SplitList(current) {
		add(d)
	}
	for _, d := range extraPathDirs {
		add(d)
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}

// stepContext renders the shell and environment for a failed step.
func stepContext(shell, cwd string, env []string) string {
	if cwd == "" {
		cwd = "(shell default)"
	}
	return fmt.Sprintf("step context: shell=%s cwd=%s uid=%d PATH=%s",
		shell, cwd, os.Geteuid(), envValue(env, "PATH"))
}

// Last assignment wins, matching how exec dedupes the environment.
func envValue(env []string, key string) string {
	prefix := key + "="
	val := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			val = kv[len(prefix):]
		}
	}
	return val
}

func makeScratch(jobID string) (string, error) {
	return os.MkdirTemp("", "deplite-job-"+jobID+"-*")
}

// expandHome resolves a leading ~ or $HOME in a working-directory value.
// The path is quoted before it reaches a shell, and the local branch hands it
// to chdir directly, so neither would expand it.
func expandHome(dir string) (string, error) {
	var rest string
	switch {
	case dir == "~", dir == "$HOME":
		rest = ""
	case strings.HasPrefix(dir, "~/"):
		rest = dir[2:]
	case strings.HasPrefix(dir, "$HOME/"):
		rest = dir[len("$HOME/"):]
	default:
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("working-directory %q: %w", dir, err)
	}
	if rest == "" {
		return home, nil
	}
	return filepath.Join(home, rest), nil
}

// readOutputs parses `key=value` lines from the step's output file.
// Lines without `=` or with non-identifier keys are skipped. Values
// pass through the masker so logged secrets don't leak into the
// captured map.
func readOutputs(path string, masker *mask.Masker) map[string]string {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	defer os.Remove(path)
	out := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := line[eq+1:]
		if !isOutputKey(key) {
			continue
		}
		out[key] = masker.Apply(val)
	}
	return out
}

func isOutputKey(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if i == 0 && !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func materializeOutputs(wf workflow.Workflow, captured workflow.StepOutputs) map[string]any {
	if len(wf.Outputs) == 0 {
		return nil
	}
	resolved := wf.ResolveOutputs(captured)
	if len(resolved) == 0 {
		return nil
	}
	out := make(map[string]any, len(resolved))
	for _, decl := range wf.Outputs {
		v, ok := resolved[decl.Name]
		if !ok {
			continue
		}
		out[decl.Name] = coerceOutput(decl.Type, v)
	}
	return out
}

func coerceOutput(t workflow.OutputType, v string) any {
	switch t {
	case workflow.OutputNumber:
		var f float64
		if _, err := fmt.Sscanf(v, "%g", &f); err == nil {
			return f
		}
	case workflow.OutputBoolean:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no", "":
			return false
		}
	}
	return v
}

func effectiveRetry(wfRetry, stepRetry *workflow.Retry) *workflow.Retry {
	if stepRetry != nil {
		return stepRetry
	}
	return wfRetry
}

func backoffDelay(r *workflow.Retry, attempt int) time.Duration {
	if r == nil {
		return 0
	}
	initial := time.Duration(r.InitialDelaySeconds) * time.Second
	if initial <= 0 {
		initial = time.Second
	}
	maxD := time.Duration(r.MaxDelaySeconds) * time.Second
	var d time.Duration
	switch r.Backoff {
	case workflow.BackoffLinear:
		d = initial * time.Duration(attempt-1)
	case workflow.BackoffExponential:
		d = initial * (1 << (attempt - 2))
	default:
		d = initial
	}
	if maxD > 0 && d > maxD {
		d = maxD
	}
	// 0-20% jitter to avoid thundering herd on shared upstreams.
	if d > 0 {
		d += time.Duration(rand.Int63n(int64(d) / 5))
	}
	return d
}

// RequireSecrets reports the first declared secret that is required but
// has no bound value. A dry run uses it to reject the same inputs a real
// run would.
func RequireSecrets(wf workflow.Workflow, supplied map[string]string) error {
	return requireSecrets(wf, supplied)
}

func requireSecrets(wf workflow.Workflow, supplied map[string]string) error {
	for _, s := range wf.Secrets {
		if !s.Required {
			continue
		}
		if _, ok := supplied[s.Name]; !ok {
			return fmt.Errorf("secret %q required but not bound", s.Name)
		}
	}
	return nil
}

// filterSecretsForStep applies per-secret scope. A secret with no
// scope is visible to every step; a secret with scope is only visible
// to steps whose id is in the list.
func filterSecretsForStep(decls []workflow.Secret, supplied map[string]string, stepID string) map[string]string {
	if len(supplied) == 0 {
		return supplied
	}
	scope := make(map[string][]string, len(decls))
	for _, d := range decls {
		scope[d.Name] = d.Scope
	}
	out := make(map[string]string, len(supplied))
	for k, v := range supplied {
		s, ok := scope[k]
		if !ok || len(s) == 0 {
			out[k] = v
			continue
		}
		if stepID == "" {
			continue
		}
		for _, id := range s {
			if id == stepID {
				out[k] = v
				break
			}
		}
	}
	return out
}
