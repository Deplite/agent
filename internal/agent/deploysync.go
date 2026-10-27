package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
)

const (
	deploySyncInterval = 15 * time.Minute
	deploySyncTimeout  = 60 * time.Second
)

// deploySyncLoop runs syncDeployState on a ticker until ctx is canceled.
func deploySyncLoop(ctx context.Context, c *apiclient.Client, s apiclient.Signer, serverPub string, store *appStore, log *slog.Logger) {
	ticker := time.NewTicker(deploySyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sctx, cancel := context.WithTimeout(ctx, deploySyncTimeout)
			syncDeployState(sctx, c, s, serverPub, store, log)
			cancel()
		}
	}
}

// syncDeployState reports each locally known app as idle, then pulls the
// verified desired manifests to seed unknown apps and log any drift. The
// server dispatches update jobs itself; the agent never self-applies here.
func syncDeployState(ctx context.Context, c *apiclient.Client, s apiclient.Signer, serverPub string, store *appStore, log *slog.Logger) {
	if local, err := store.load(); err != nil {
		log.Warn("app state load failed", "error", err)
	} else {
		for appID, rec := range local {
			rep := apiclient.DeviceReport{
				ApplicationID:    appID,
				CurrentReleaseID: rec.ReleaseID,
				State:            apiclient.DeviceIdle,
			}
			if err := c.ReportDeviceState(ctx, s, rep); err != nil {
				log.Warn("device report failed", "applicationId", appID, "error", err)
			}
		}
	}

	apps, err := c.GetDesiredDeploys(ctx, s, serverPub)
	if err != nil {
		log.Warn("desired manifest verification skipped some apps", "error", err)
	}
	for _, app := range apps {
		rec, ok := store.get(app.ApplicationID)
		if !ok && app.Current != nil {
			seed := appRecord{
				ReleaseID: app.Current.ReleaseID,
				Version:   app.Current.Version,
				Sequence:  app.Current.Sequence,
				Channel:   app.Channel,
			}
			stored, err := store.putIfAbsent(app.ApplicationID, seed)
			switch {
			case err != nil:
				log.Warn("seed app state failed", "applicationId", app.ApplicationID, "error", err)
			case stored:
				log.Info("seeded app state from server", "applicationId", app.ApplicationID, "sequence", seed.Sequence)
				rec, ok = seed, true
			default:
				// Lost the race to a concurrent put (e.g. persistOTAState); read back
				// its newer record instead of trusting this stale server snapshot.
				rec, ok = store.get(app.ApplicationID)
			}
		}
		if app.Desired == nil {
			continue
		}
		switch {
		case ok && rec.Sequence != app.Desired.Sequence:
			log.Info("app update pending", "applicationId", app.ApplicationID, "currentSequence", rec.Sequence, "desiredSequence", app.Desired.Sequence)
		case !ok:
			log.Info("app update pending; no local baseline", "applicationId", app.ApplicationID, "desiredSequence", app.Desired.Sequence)
		}
	}
}

// persistOTAState records the installed release after a successful OTA job
// and reports it. It is a no-op for jobs whose params are not an OTA update
// (missing release_id or sequence).
func persistOTAState(c *apiclient.Client, s apiclient.Signer, store *appStore, params map[string]any, log *slog.Logger) {
	releaseID, _ := params["release_id"].(string)
	seq, hasSeq := paramInt64(params["sequence"])
	if releaseID == "" || !hasSeq {
		return
	}
	appID, _ := params["application_id"].(string)
	if appID == "" {
		log.Debug("application_id missing; skipping device report")
		return
	}
	version, _ := params["version"].(string)
	channel, _ := params["channel"].(string)
	if err := store.put(appID, appRecord{ReleaseID: releaseID, Version: version, Sequence: seq, Channel: channel}); err != nil {
		log.Warn("persist app state failed", "applicationId", appID, "error", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), deploySyncTimeout)
	defer cancel()
	rep := apiclient.DeviceReport{
		ApplicationID:    appID,
		CurrentReleaseID: releaseID,
		State:            apiclient.DeviceIdle,
	}
	if err := c.ReportDeviceState(ctx, s, rep); err != nil {
		log.Warn("device report failed", "applicationId", appID, "error", err)
	}
}

// paramInt64 converts a numeric workflow param to int64. JSON decodes
// numbers as float64, so that is the common case.
func paramInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}
