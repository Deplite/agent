package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/systemd"
)

type installFakeOps struct {
	lookErrors map[string]error
	commands   []string
	runError   error
}

func (f *installFakeOps) IsDir(path string) bool { return path == "/run/systemd/system" }
func (f *installFakeOps) LookPath(name string) (string, error) {
	if err := f.lookErrors[name]; err != nil {
		return "", err
	}
	return "/fake/" + name, nil
}
func (f *installFakeOps) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (f *installFakeOps) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(append([]string{name}, args...), " "))
	return nil, f.runError
}
func (*installFakeOps) WriteFile(string, []byte, os.FileMode) error { return nil }
func (*installFakeOps) CreateTemp([]byte) (string, func(), error) {
	return "/tmp/unit", func() {}, nil
}
func (*installFakeOps) MkdirAll(string, os.FileMode) error { return nil }
func (*installFakeOps) Chown(string, int, int) error       { return nil }
func (*installFakeOps) Remove(string) error                { return nil }

func fakeInstallDeps(ops systemd.Ops, cfg systemd.Config) installDeps {
	return installDeps{
		ServiceConfig: cfg, ServiceOps: ops, Out: io.Discard,
		Load: func(string) (credstore.Identity, bool, error) { return credstore.Identity{}, false, nil },
		Register: func(context.Context, agent.InstallOptions) (credstore.Identity, error) {
			return credstore.Identity{AgentID: "new-agent"}, nil
		},
		MkdirAll: func(string, os.FileMode) error { return nil },
	}
}

func TestInstallPreflightFailureDoesNotRegister(t *testing.T) {
	ops := &installFakeOps{lookErrors: map[string]error{"systemctl": errors.New("missing")}}
	cfg := systemd.Config{
		GOOS: "linux", EUID: 0, UID: 0, GID: 0, User: "root",
		Executable: "/usr/local/bin/deplite-agent", DataDir: "/var/lib/deplite-agent",
		WorkflowsDir: "/var/lib/deplite-agent/workflows", UnitPath: "/etc/systemd/system/deplite-agent.service",
	}
	deps := fakeInstallDeps(ops, cfg)
	registerCalls := 0
	deps.Register = func(context.Context, agent.InstallOptions) (credstore.Identity, error) {
		registerCalls++
		return credstore.Identity{}, nil
	}
	_, _, err := installMachine(context.Background(), installOptions{
		DataDir: cfg.DataDir, WorkflowsDir: cfg.WorkflowsDir, InstallCode: "one-time-code",
	}, deps)
	if err == nil {
		t.Fatal("install succeeded without systemctl")
	}
	if registerCalls != 0 {
		t.Fatalf("registration was called %d times after preflight failure", registerCalls)
	}
}

func TestInstallSudoAuthenticationFailureDoesNotRegister(t *testing.T) {
	ops := &installFakeOps{lookErrors: map[string]error{}, runError: errors.New("authentication failed")}
	cfg := systemd.Config{
		GOOS: "linux", EUID: 1000, UID: 1000, GID: 1000, User: "alice",
		Executable: "/usr/local/bin/deplite-agent", DataDir: "/home/alice/.config/deplite-agent",
		WorkflowsDir: "/home/alice/.config/deplite-agent/workflows", UnitPath: "/etc/systemd/system/deplite-agent.service",
	}
	deps := fakeInstallDeps(ops, cfg)
	registerCalls := 0
	deps.Register = func(context.Context, agent.InstallOptions) (credstore.Identity, error) {
		registerCalls++
		return credstore.Identity{}, nil
	}
	_, _, err := installMachine(context.Background(), installOptions{
		DataDir: cfg.DataDir, WorkflowsDir: cfg.WorkflowsDir, InstallCode: "one-time-code",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "sudo 인증") {
		t.Fatalf("install error = %v, want sudo preflight failure", err)
	}
	if registerCalls != 0 {
		t.Fatalf("registration was called %d times after sudo preflight failure", registerCalls)
	}
}

func TestInstallExistingCredentialsCodeBranches(t *testing.T) {
	identity := credstore.Identity{AgentID: "existing-agent"}
	load := func(string) (credstore.Identity, bool, error) { return identity, true, nil }
	registerCalls := 0
	register := func(context.Context, agent.InstallOptions) (credstore.Identity, error) {
		registerCalls++
		return credstore.Identity{}, nil
	}
	base := systemd.Config{GOOS: "darwin", NoService: true}
	deps := fakeInstallDeps(&installFakeOps{}, base)
	deps.Load, deps.Register = load, register
	opts := installOptions{DataDir: "/data", WorkflowsDir: "/data/workflows", InstallCode: "unused-code"}
	if _, _, err := installMachine(context.Background(), opts, deps); err == nil || !strings.Contains(err.Error(), "서비스만 설정") {
		t.Fatalf("install with existing credentials and code error = %v", err)
	}
	if registerCalls != 0 {
		t.Fatalf("registration called %d times", registerCalls)
	}

	var madeDir string
	deps.MkdirAll = func(path string, _ os.FileMode) error { madeDir = path; return nil }
	opts.InstallCode = ""
	got, plan, err := installMachine(context.Background(), opts, deps)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "existing-agent" || plan.Enabled || madeDir != opts.WorkflowsDir || registerCalls != 0 {
		t.Fatalf("configure-only result = id:%+v plan:%+v dir:%q register calls:%d", got, plan, madeDir, registerCalls)
	}
}

func TestInstallCodeConflictStopsBeforeServicePreparation(t *testing.T) {
	ops := &installFakeOps{lookErrors: map[string]error{}}
	cfg := systemd.Config{
		GOOS: "linux", EUID: 1000, UID: 1000, GID: 1000, User: "alice",
		Executable: "/usr/local/bin/deplite-agent", DataDir: "/home/alice/.config/deplite-agent",
		WorkflowsDir: "/home/alice/.config/deplite-agent/workflows", UnitPath: "/etc/systemd/system/deplite-agent.service",
	}
	deps := fakeInstallDeps(ops, cfg)
	deps.Load = func(string) (credstore.Identity, bool, error) {
		return credstore.Identity{AgentID: "existing-agent"}, true, nil
	}
	confirmCalls, registerCalls := 0, 0
	deps.Confirm = func(string) bool { confirmCalls++; return true }
	deps.Register = func(context.Context, agent.InstallOptions) (credstore.Identity, error) {
		registerCalls++
		return credstore.Identity{}, nil
	}
	_, _, err := installMachine(context.Background(), installOptions{
		DataDir: cfg.DataDir, WorkflowsDir: cfg.WorkflowsDir, InstallCode: "already-used",
	}, deps)
	if err == nil || !strings.Contains(err.Error(), "서비스만 설정") {
		t.Fatalf("install error = %v, want existing credential conflict", err)
	}
	if len(ops.commands) != 0 || confirmCalls != 0 || registerCalls != 0 {
		t.Fatalf("service or registration work happened before conflict: commands=%v confirmations=%d registrations=%d", ops.commands, confirmCalls, registerCalls)
	}
}

func TestInstallDirsReturnsAbsolutePaths(t *testing.T) {
	data, workflows, err := installDirs(filepath.Join("relative", "data"), filepath.Join("relative", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(data) || !filepath.IsAbs(workflows) {
		t.Fatalf("install dirs are not absolute: %q %q", data, workflows)
	}
	if workflows != filepath.Join("relative", "workflows") && filepath.Base(workflows) != "workflows" {
		t.Fatalf("unexpected workflow directory %q", workflows)
	}
}

func TestDefaultDataDir(t *testing.T) {
	home, err := effectiveHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() == 0 {
			t.Setenv("HOME", "/tmp/deplite-unrelated-home")
			t.Setenv("XDG_CONFIG_HOME", "/tmp/deplite-unrelated-xdg")
			got, err := defaultDataDir()
			want := filepath.Join(home, ".config", "deplite-agent")
			if err != nil || got != want {
				t.Fatalf("root default data dir = %q, %v", got, err)
			}
			return
		}
		t.Setenv("XDG_CONFIG_HOME", "/tmp/deplite-xdg")
		got, err := defaultDataDir()
		if err != nil || got != "/tmp/deplite-xdg/deplite-agent" {
			t.Fatalf("XDG default data dir = %q, %v", got, err)
		}
		t.Setenv("XDG_CONFIG_HOME", "")
		got, err = defaultDataDir()
		if err != nil || got != filepath.Join(home, ".config", "deplite-agent") {
			t.Fatalf("user default data dir = %q, %v", got, err)
		}
	case "darwin":
		got, err := defaultDataDir()
		want := filepath.Join(home, "Library", "Application Support", "deplite-agent")
		if err != nil || got != want {
			t.Fatalf("macOS default data dir = %q, want %q, err %v", got, want, err)
		}
	}
}
