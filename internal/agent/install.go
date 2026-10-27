package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/signing"
)

type InstallOptions struct {
	BaseURL     string
	DataDir     string
	InstallCode string
	Name        string
	Version     string
}

// Install exchanges a one-time install code for a permanent agent
// identity. Refuses to overwrite an existing data dir so a working
// agent is never silently wiped.
func Install(ctx context.Context, opts InstallOptions) (credstore.Identity, error) {
	if opts.InstallCode == "" {
		return credstore.Identity{}, errors.New("install: one-time install code is required")
	}
	if opts.BaseURL == "" {
		return credstore.Identity{}, errors.New("install: base URL is required")
	}

	store := credstore.New(opts.DataDir)
	if store.Exists() {
		return credstore.Identity{}, fmt.Errorf("install: data directory %q already holds credentials; remove it to register again", opts.DataDir)
	}

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		return credstore.Identity{}, err
	}
	pubPEM, err := kp.PublicKeyPEM()
	if err != nil {
		return credstore.Identity{}, err
	}

	host, _ := os.Hostname()
	name := opts.Name
	if name == "" {
		name = host
	}

	resp, err := apiclient.New(opts.BaseURL).Enroll(ctx, opts.InstallCode, apiclient.EnrollRequest{
		Name:         name,
		Hostname:     host,
		OS:           runtime.GOOS + "/" + runtime.GOARCH,
		AgentVersion: opts.Version,
		PublicKey:    pubPEM,
	})
	if err != nil {
		return credstore.Identity{}, fmt.Errorf("install: register: %w", err)
	}

	id := credstore.Identity{
		AgentID:            resp.AgentID,
		OrganizationID:     resp.OrganizationID,
		BaseURL:            opts.BaseURL,
		ServerPublicKeyPEM: resp.ServerPublicKeyPEM,
	}
	if err := store.Save(id, kp); err != nil {
		return credstore.Identity{}, fmt.Errorf("install: persist credentials: %w", err)
	}
	return id, nil
}
