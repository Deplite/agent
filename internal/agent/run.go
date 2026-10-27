package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/approval"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/files"
	"github.com/Deplite/agent/internal/joblog"
	"github.com/Deplite/agent/internal/limiter"
	"github.com/Deplite/agent/internal/mask"
	"github.com/Deplite/agent/internal/runner"
	"github.com/Deplite/agent/internal/workflow"
)

type StartOptions struct {
	DataDir           string
	WorkflowsDir      string
	Version           string
	HeartbeatInterval time.Duration
	// ShutdownGrace is the maximum time Start blocks after ctx is
	// canceled, waiting for an in-flight job to finish. Step processes
	// continue running until they exit or this deadline lapses.
	ShutdownGrace time.Duration
	// DisableDeploySync turns off app-deploy state reconciliation for
	// hosts that only run workflows.
	DisableDeploySync bool
}

func Start(ctx context.Context, opts StartOptions) error {
	store := credstore.New(opts.DataDir)
	if !store.Exists() {
		return fmt.Errorf("start: no credentials at %q; run 'deplite-agent install' first", opts.DataDir)
	}
	id, kp, err := store.Load()
	if err != nil {
		return err
	}

	client := apiclient.New(id.BaseURL)
	signer := newSigner(id.AgentID, kp)
	approvalVerifier := approval.NewVerifier(nil)
	log := slog.Default().With("agentId", id.AgentID)

	wfDir := opts.WorkflowsDir
	if wfDir == "" {
		wfDir = filepath.Join(opts.DataDir, "workflows")
	}

	host, _ := osHostname()
	if err := client.UpdateIdentity(ctx, signer, apiclient.IdentityPatch{
		Hostname:     host,
		OS:           runtime.GOOS + "/" + runtime.GOARCH,
		AgentVersion: opts.Version,
	}); err != nil {
		log.Warn("identity update failed", "error", err)
	}

	state := newStateWriter(opts.DataDir, opts.Version)
	defer state.remove()

	reportWorkflows(ctx, client, signer, wfDir, state, log)

	heartbeat := opts.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = 30 * time.Second
	}
	grace := opts.ShutdownGrace
	if grace <= 0 {
		grace = 30 * time.Second
	}

	// jobLoop uses its own ctx so we can keep an in-flight job running
	// briefly after the main ctx is canceled (SIGTERM). After the grace
	// window we force-cancel.
	jobCtx, cancelJobs := context.WithCancel(context.Background())
	defer cancelJobs()
	jobsDone := make(chan struct{})

	limits := limiter.New(filepath.Join(opts.DataDir, "limits"))
	dedup := newJobDedup(1024)
	tracker := newJobTracker()
	apps := newAppStore(opts.DataDir)
	joblog.LocalDir = resolveLogDir(opts.DataDir)

	// onConnect refreshes deploy state each time the SSE stream connects,
	// off the event loop so a slow sync never stalls event handling.
	onConnect := func() {
		state.update(func(r *RunState) {
			r.StreamConnected = true
			r.StreamConnectedAt = time.Now().UTC()
		})
		if opts.DisableDeploySync {
			return
		}
		go func() {
			sctx, cancel := context.WithTimeout(ctx, deploySyncTimeout)
			defer cancel()
			syncDeployState(sctx, client, signer, id.ServerPublicKeyPEM, apps, log)
		}()
	}

	jobs := make(chan apiclient.DeployPayload, 4)
	go heartbeatLoop(ctx, client, signer, heartbeat, state, log)
	go workflowWatcher(ctx, client, signer, wfDir, state, log)
	if opts.DisableDeploySync {
		log.Info("app deploy sync disabled")
	} else {
		go deploySyncLoop(ctx, client, signer, id.ServerPublicKeyPEM, apps, log)
	}
	go func() {
		jobLoop(jobCtx, client, signer, jobs, wfDir, limits, tracker, apps, state, approvalVerifier, id.AgentID, log)
		close(jobsDone)
	}()

	err = streamLoop(ctx, client, signer, id.ServerPublicKeyPEM, jobs, wfDir, dedup, tracker, state, onConnect, log)
	state.update(func(r *RunState) { r.StreamConnected = false })
	close(jobs)

	// Give a running step a moment to wind down, then force-cancel.
	log.Info("waiting for in-flight job to drain", "grace", grace)
	select {
	case <-jobsDone:
	case <-time.After(grace):
		log.Warn("drain deadline exceeded; force-cancelling job")
		cancelJobs()
		<-jobsDone
	}
	return err
}

// reportWorkflows publishes the catalog view of every workflow in dir.
// The report replaces the server-side set, so an empty one is only sent
// when the directory genuinely holds no workflow: a missing directory or
// a batch where every file failed to load leaves the existing catalog
// alone rather than wiping it over a typo in --workflows-dir.
func reportWorkflows(ctx context.Context, c *apiclient.Client, s apiclient.Signer, dir string, state *stateWriter, log *slog.Logger) {
	wfs, bad := workflow.Scan(dir)
	for _, e := range bad {
		log.Error("workflow load failed", "path", e.Path, "error", e.Err)
	}
	state.update(func(r *RunState) {
		r.WorkflowsReported = len(wfs)
		r.WorkflowsInvalid = len(bad)
	})
	if len(wfs) == 0 {
		if _, err := os.Stat(dir); err != nil {
			log.Error("workflows directory unreadable; keeping the existing catalog", "dir", dir, "error", err)
			return
		}
		if len(bad) > 0 {
			log.Error("every workflow file failed to load; keeping the existing catalog", "dir", dir, "failed", len(bad))
			return
		}
	}
	reported := make([]apiclient.ReportedWorkflow, 0, len(wfs))
	for _, w := range wfs {
		reported = append(reported, catalogView(w))
	}
	res, err := c.ReportWorkflows(ctx, s, reported)
	if err != nil {
		log.Warn("workflow report failed", "error", err)
		return
	}
	for _, r := range res.Rejected {
		log.Warn("workflow rejected by server", "workflow", r.Name, "code", r.Code, "reason", r.Reason)
	}
	log.Info("workflows reported", "count", res.Count, "rejected", len(res.Rejected))
}

func heartbeatLoop(ctx context.Context, c *apiclient.Client, s apiclient.Signer, period time.Duration, state *stateWriter, log *slog.Logger) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	beat := func(first bool) {
		err := c.Heartbeat(ctx, s)
		state.update(func(r *RunState) {
			r.LastHeartbeatAt = time.Now().UTC()
			if err != nil {
				r.LastHeartbeatError = err.Error()
			} else {
				r.LastHeartbeatError = ""
			}
		})
		if err != nil {
			if first {
				log.Warn("initial heartbeat failed", "error", err)
			} else {
				log.Warn("heartbeat failed", "error", err)
			}
		}
	}
	beat(true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beat(false)
		}
	}
}

// ErrAgentRevoked signals that the backend has rejected this agent's
// credentials. The caller should exit instead of reconnecting.
var ErrAgentRevoked = errors.New("agent: credentials revoked by server")

func streamLoop(ctx context.Context, c *apiclient.Client, s apiclient.Signer, serverPub string, jobs chan<- apiclient.DeployPayload, wfDir string, dedup *jobDedup, tracker *jobTracker, state *stateWriter, onConnect func(), log *slog.Logger) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		events := make(chan apiclient.Event, 8)
		errCh := make(chan error, 1)
		streamCtx, cancel := context.WithCancel(ctx)
		go func() {
			errCh <- c.Stream(streamCtx, s, events)
		}()
		log.Info("stream connected")
		backoff = time.Second
		if onConnect != nil {
			onConnect()
		}

	dispatch:
		for {
			select {
			case <-ctx.Done():
				cancel()
				return nil
			case e, ok := <-events:
				if !ok {
					break dispatch
				}
				handleEvent(streamCtx, c, s, serverPub, e, jobs, wfDir, dedup, tracker, state, log)
			case err := <-errCh:
				cancel()
				if errors.Is(err, context.Canceled) || ctx.Err() != nil {
					return nil
				}
				// Auth failures mean reconnecting will never help; stop
				// so an operator can re-enroll instead of hammering the
				// backend.
				var apiErr *apiclient.APIError
				if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
					log.Error("agent credentials rejected; stopping", "status", apiErr.StatusCode, "body", apiErr.Body)
					return ErrAgentRevoked
				}
				log.Warn("stream ended; will reconnect", "error", err, "backoff", backoff)
				goto reconnect
			}
		}

	reconnect:
		cancel()
		state.update(func(r *RunState) { r.StreamConnected = false })
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// cancelPayload is the (unsigned) data of a 'cancel' SSE event. reason is
// nullable on the wire.
type cancelPayload struct {
	JobID      string  `json:"job_id"`
	Reason     *string `json:"reason"`
	Superseded bool    `json:"superseded"`
	Actor      string  `json:"actor"`
}

func (c cancelPayload) reasonText() string {
	if c.Reason == nil {
		return ""
	}
	return *c.Reason
}

func handleEvent(ctx context.Context, c *apiclient.Client, s apiclient.Signer, serverPub string, e apiclient.Event, jobs chan<- apiclient.DeployPayload, wfDir string, dedup *jobDedup, tracker *jobTracker, state *stateWriter, log *slog.Logger) {
	switch e.Name {
	case "ping":
		// keepalive
	case "probe":
		var probe struct {
			ProbeID string `json:"probe_id"`
		}
		if err := json.Unmarshal(e.Data, &probe); err != nil {
			log.Warn("probe event parse failed", "error", err)
			return
		}
		if strings.TrimSpace(probe.ProbeID) == "" {
			log.Warn("probe event missing probe_id")
			return
		}
		go func(probeID string) {
			probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.HeartbeatProbe(probeCtx, s, probeID); err != nil {
				log.Warn("probe heartbeat failed", "error", err)
			}
		}(probe.ProbeID)
	case "deploy":
		payload, err := apiclient.ParseAndVerifyDeploy(e.Data, serverPub)
		if err != nil {
			log.Warn("deploy verify failed", "error", err)
			return
		}
		if dedup.seen(payload.JobID) {
			log.Info("duplicate job ignored", "jobId", payload.JobID)
			return
		}
		select {
		case jobs <- payload:
			tracker.queue(payload.JobID)
			log.Info("job queued", "jobId", payload.JobID, "workflow", payload.WorkflowName)
		default:
			log.Warn("job queue full; rejecting", "jobId", payload.JobID)
			reportRejected(ctx, c, s, payload.JobID, "agent job queue full", "", "", 0, log)
		}
	case "cancel":
		var cp cancelPayload
		if err := json.Unmarshal(e.Data, &cp); err != nil {
			log.Warn("cancel event parse failed", "error", err)
			return
		}
		found, running := tracker.cancel(cp.JobID)
		switch {
		case !found:
			log.Debug("cancel for unknown or finished job", "jobId", cp.JobID)
		case cp.Superseded:
			log.Info("job superseded by newer release", "jobId", cp.JobID, "running", running, "reason", cp.reasonText())
		default:
			log.Info("job cancel requested", "jobId", cp.JobID, "running", running, "reason", cp.reasonText(), "actor", cp.Actor)
		}
	case "sync_workflows", "workflows-refresh":
		log.Info("workflow resync requested")
		reportWorkflows(ctx, c, s, wfDir, state, log)
	case "revoke":
		log.Warn("agent revoked by server")
		os.Exit(0)
	default:
		log.Debug("unknown event", "name", e.Name)
	}
}

func jobLoop(ctx context.Context, c *apiclient.Client, s apiclient.Signer, jobs <-chan apiclient.DeployPayload, wfDir string, limits *limiter.Manager, tracker *jobTracker, store *appStore, state *stateWriter, verifier *approval.Verifier, agentID string, log *slog.Logger) {
	masker := mask.New()
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			if tracker.isCanceled(j.JobID) {
				log.Info("job canceled before start; skipping", "jobId", j.JobID)
				tracker.finish(j.JobID)
				continue
			}
			state.update(func(r *RunState) {
				r.CurrentJobID = j.JobID
				r.CurrentWorkflow = j.WorkflowName
			})
			runOneJob(ctx, c, s, j, wfDir, limits, masker, tracker, store, verifier, agentID, log)
			state.update(func(r *RunState) {
				r.CurrentJobID = ""
				r.CurrentWorkflow = ""
			})
		}
	}
}

func runOneJob(ctx context.Context, c *apiclient.Client, s apiclient.Signer, payload apiclient.DeployPayload, wfDir string, limits *limiter.Manager, masker *mask.Masker, tracker *jobTracker, store *appStore, verifier *approval.Verifier, agentID string, log *slog.Logger) {
	jobLog := log.With("jobId", payload.JobID, "workflow", payload.WorkflowName)
	// Guarantee every runOneJob exit forgets the job, including the early
	// reject returns below (workflow not found, force checks, rate limit).
	defer tracker.finish(payload.JobID)
	wfs, _ := workflow.Scan(wfDir)
	var wf *workflow.Workflow
	for i := range wfs {
		if wfs[i].Name == payload.WorkflowName {
			wf = &wfs[i]
			break
		}
	}
	if wf == nil {
		_, _ = c.ReportJobResult(ctx, s, payload.JobID, apiclient.JobResult{
			Status:       apiclient.JobFailed,
			ErrorMessage: "workflow not found: " + payload.WorkflowName,
		})
		return
	}

	if msg := callDenied(wf, payload); msg != "" {
		jobLog.Warn("call rejected by local workflow declaration", "ref", payload.Ref)
		reportRejected(ctx, c, s, payload.JobID, msg, "", "", 0, jobLog)
		return
	}
	var approvalLog string
	if wf.ApprovalPolicy() != nil {
		params, method, keyID, err := verifyWorkflowApproval(verifier, wf, agentID, payload)
		if err != nil {
			var paramsErr *paramValidationError
			if errors.As(err, &paramsErr) {
				jobLog.Warn("param validation failed")
				reportFailed(c, s, payload.JobID, paramsErr.Error(), jobLog)
				return
			}
			var rejected *approval.Rejection
			if !errors.As(err, &rejected) {
				rejected = &approval.Rejection{Code: approval.CodeInvalid, Message: "approval is invalid"}
			}
			jobLog.Warn("approval rejected")
			reportRejected(ctx, c, s, payload.JobID, rejected.Message, rejected.Code, "", 0, jobLog)
			return
		}
		payload.Params = params
		approvalLog = fmt.Sprintf("approval verified (method=%s, keyId=%s)", method, keyID)
	}
	if payload.Force {
		jobLog.Info("forced execution", "reason", payload.ForceReason)
	}

	var bypassed []string
	if payload.Force {
		if !wf.ForceBypassAllowed() {
			reportRejected(ctx, c, s, payload.JobID, "force bypass is disabled for this workflow (force-allowed: false)", "", "", 0, jobLog)
			return
		}
		if strings.TrimSpace(payload.ForceReason) == "" {
			reportRejected(ctx, c, s, payload.JobID, "force requires force_reason", "", "", 0, jobLog)
			return
		}
		bypassed = limiter.BypassTypes(wf)
		if len(bypassed) > 0 {
			jobLog.Warn("limits bypassed by force", "bypassed", bypassed, "reason", payload.ForceReason)
		}
	} else {
		dec, err := limits.TryAcquire(wf, time.Now())
		if err != nil {
			reportRejected(ctx, c, s, payload.JobID, "limiter: "+err.Error(), "", "", 0, jobLog)
			return
		}
		if !dec.Allowed {
			retry := int(dec.RetryAfter.Seconds())
			if retry < 1 {
				retry = 1
			}
			msg := fmt.Sprintf("rate limited by %s; retry after %ds", dec.LimitType, retry)
			jobLog.Warn("job rate limited", "limitType", dec.LimitType, "retryAfterSeconds", retry)
			reportRejected(ctx, c, s, payload.JobID, msg, "rate_limited", dec.LimitType, retry, jobLog)
			return
		}
	}

	shipper := joblog.New(c, s)
	if approvalLog != "" {
		jobLog.Info(approvalLog)
		shipper.Append(payload.JobID, apiclient.LogStreamSystem, "", approvalLog, apiclient.LogLevelInfo)
	}
	shipCtx, shipCancel := context.WithCancel(ctx)
	shipDone := make(chan struct{})
	go func() {
		shipper.Run(shipCtx, payload.JobID)
		close(shipDone)
	}()

	// jobCtx lets a 'cancel' event stop this job's file resolution and
	// runner without waiting for process shutdown.
	jobCtx, jobCancel, _ := tracker.running(ctx, payload.JobID)
	defer jobCancel()

	teardown := func(status apiclient.JobStatus) {
		shipCancel()
		<-shipDone
		_ = shipper.Flush(context.Background(), payload.JobID)
		shipper.Forget(payload.JobID)
		if !payload.Force {
			if err := limits.Release(wf, time.Now(), string(status)); err != nil {
				jobLog.Warn("limiter release failed", "error", err)
			}
		}
	}

	if _, err := c.ReportJobResult(ctx, s, payload.JobID, apiclient.JobResult{Status: apiclient.JobRunning}); err != nil {
		jobLog.Warn("could not mark running", "error", err)
	}

	secrets := resolveSecrets(wf.Secrets)

	jobFilesDir := filepath.Join(filepath.Dir(joblog.LocalDir), "files", payload.JobID)
	inputDir := filepath.Join(jobFilesDir, "in")
	outputDir := filepath.Join(jobFilesDir, "out")
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		jobLog.Warn("output dir creation failed", "error", err)
	}
	defer os.RemoveAll(jobFilesDir)

	// Capture what the artifact has to be checked against before WalkInputs
	// rewrites the FileRef into a local path.
	verification, verifyArtifactBeforeRun := artifactVerificationFor(payload.Params)

	resolvedParams := payload.Params
	if resolvedParams != nil {
		resolver := files.NewResolver(c, s, inputDir)
		resolveCtx, cancelResolve := context.WithTimeout(jobCtx, 10*time.Minute)
		walked, walkErr := resolver.WalkInputs(resolveCtx, resolvedParams)
		cancelResolve()
		if walkErr != nil {
			jobLog.Warn("input file resolution failed", "error", walkErr)
			teardown(apiclient.JobFailed)
			if tracker.isCanceled(payload.JobID) {
				jobLog.Info("job canceled; skipping result report")
			} else {
				reportRejected(ctx, c, s, payload.JobID, "input files: "+walkErr.Error(), "", "", 0, jobLog)
			}
			return
		}
		if m, ok := walked.(map[string]any); ok {
			resolvedParams = m
		}
	}

	var artifactRes artifactResult
	if verifyArtifactBeforeRun {
		path, resolved := resolvedParams["artifact"].(string)
		err := errors.New("the artifact was not resolved to a local file, so it cannot be verified")
		if resolved {
			artifactRes, err = verifyArtifact(path, verification, artifactPolicyFromEnv())
		}
		for _, w := range artifactRes.warnings {
			jobLog.Warn("artifact verification", "note", w)
			shipper.Append(payload.JobID, apiclient.LogStreamSystem, "", w, apiclient.LogLevelWarn)
		}
		if artifactRes.signatureVerified() {
			msg := "artifact signature verified with " + artifactRes.verifiedWith
			jobLog.Info(msg)
			shipper.Append(payload.JobID, apiclient.LogStreamSystem, "", msg, apiclient.LogLevelInfo)
		}
		if err != nil {
			jobLog.Warn("artifact verification failed", "error", err)
			shipper.Append(payload.JobID, apiclient.LogStreamSystem, "", err.Error(), apiclient.LogLevelError)
			teardown(apiclient.JobFailed)
			if tracker.isCanceled(payload.JobID) {
				jobLog.Info("job canceled; skipping result report")
			} else {
				reportFailed(c, s, payload.JobID, err.Error(), jobLog)
			}
			return
		}
	}

	if wf.Env == nil {
		wf.Env = map[string]string{}
	}
	wf.Env["DEPLITE_OUTPUT_DIR"] = outputDir
	if verifyArtifactBeforeRun {
		// Lets a workflow skip a check the agent already did while an older
		// agent, which sets nothing, still runs its own. Assigned after the
		// yaml is parsed so a workflow's own env block cannot claim a check
		// that did not happen, and params can never collide because they are
		// injected under DEPLITE_PARAM_.
		wf.Env["DEPLITE_ARTIFACT_SIGNATURE_VERIFIED"] = envFlag(artifactRes.signatureVerified())
		wf.Env["DEPLITE_ARTIFACT_CHECKSUM_VERIFIED"] = envFlag(artifactRes.checksumVerified)
	}

	result := runner.Run(jobCtx, *wf, payload.JobID, resolvedParams, secrets, shipper, masker, payload.Debug)

	if manifest, err := files.ReadManifest(outputDir); err != nil {
		jobLog.Warn("output manifest read failed", "error", err)
	} else if manifest != nil {
		uploader := files.NewUploader(c, s, payload.JobID)
		upCtx, cancelUp := context.WithTimeout(context.Background(), 10*time.Minute)
		uploaded, upErr := uploader.WalkOutputs(upCtx, manifest, outputDir)
		cancelUp()
		if upErr != nil {
			jobLog.Warn("output file upload failed", "error", upErr)
		} else if m, ok := uploaded.(map[string]any); ok {
			if result.Outputs == nil {
				result.Outputs = m
			} else {
				for k, v := range m {
					result.Outputs[k] = v
				}
			}
		}
	}

	teardown(result.Status)

	if tracker.isCanceled(payload.JobID) {
		jobLog.Info("job canceled; skipping final result report", "status", result.Status)
		joblog.EnforceRetention(wf.Retention())
		return
	}

	finalCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report := apiclient.JobResult{Status: result.Status, ExitCode: &result.ExitCode}
	if result.Error != "" {
		report.ErrorMessage = result.Error
	}
	if len(result.Outputs) > 0 {
		report.Output = result.Outputs
	}
	if len(bypassed) > 0 {
		report.BypassedLimits = bypassed
	}
	if _, err := c.ReportJobResult(finalCtx, s, payload.JobID, report); err != nil {
		jobLog.Error("could not report result", "error", err)
	} else {
		jobLog.Info("job finished", "status", result.Status, "exitCode", result.ExitCode)
	}

	if result.Status == apiclient.JobSuccess {
		persistOTAState(c, s, store, payload.Params, jobLog)
	}

	joblog.EnforceRetention(wf.Retention())
}

// callDenied reports why the workflow's own yaml refuses this job, or ""
// when it permits it. The local yaml is the enforcement point: the backend
// checks the same thing first, but its copy of on: is a report this agent
// sent, not a source of truth — same reasoning as ResolveParams. Legacy
// trigger jobs arrive with no via at all and predate on:, so they keep
// their existing behavior.
func callDenied(wf *workflow.Workflow, payload apiclient.DeployPayload) string {
	if payload.Via != apiclient.ViaRun {
		return ""
	}
	if !wf.Callable() {
		return "workflow " + wf.Name + " does not declare on.webhook, so it cannot be called from outside the host"
	}
	if !wf.AllowsRef(payload.Ref) {
		return fmt.Sprintf("ref %q is outside the refs declared in on.webhook", payload.Ref)
	}
	return ""
}

func reportFailed(c *apiclient.Client, s apiclient.Signer, jobID, msg string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.ReportJobResult(ctx, s, jobID, apiclient.JobResult{Status: apiclient.JobFailed, ErrorMessage: msg}); err != nil {
		log.Warn("could not report failed result", "error", err)
	}
}

func reportRejected(ctx context.Context, c *apiclient.Client, s apiclient.Signer, jobID, msg, reason, limitType string, retryAfter int, log *slog.Logger) {
	r := apiclient.JobResult{
		Status:       apiclient.JobRejected,
		ErrorMessage: msg,
	}
	if reason != "" {
		r.Reason = reason
	}
	if limitType != "" {
		r.LimitType = limitType
	}
	if retryAfter > 0 {
		ra := retryAfter
		r.RetryAfterSeconds = &ra
	}
	reportCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ctx
	if _, err := c.ReportJobResult(reportCtx, s, jobID, r); err != nil {
		log.Warn("could not report rejected result", "error", err)
	}
}

func resolveSecrets(decls []workflow.Secret) map[string]string {
	if len(decls) == 0 {
		return nil
	}
	out := make(map[string]string, len(decls))
	for _, d := range decls {
		if v := os.Getenv("DEPLITE_SECRET_" + d.Name); v != "" {
			out[d.Name] = v
		}
	}
	return out
}

var osHostname = func() (string, error) { return hostnameImpl() }

func resolveLogDir(dataDir string) string {
	if v := os.Getenv("DEPLITE_LOG_DIR"); v != "" {
		return filepath.Join(v, "jobs")
	}
	if fi, err := os.Stat("/logs"); err == nil && fi.IsDir() {
		return "/logs/jobs"
	}
	return filepath.Join(dataDir, "logs", "jobs")
}

func workflowWatcher(ctx context.Context, c *apiclient.Client, s apiclient.Signer, dir string, state *stateWriter, log *slog.Logger) {
	changes := make(chan struct{}, 1)
	go func() {
		if err := workflow.Watch(ctx, dir, 500*time.Millisecond, changes); err != nil {
			log.Debug("workflow watcher unavailable", "error", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
			log.Info("workflow change detected; resyncing")
			reportWorkflows(ctx, c, s, dir, state, log)
		}
	}
}
