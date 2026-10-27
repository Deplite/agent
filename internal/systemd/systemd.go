package systemd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

// UnitPath is the system-wide service unit installed by the CLI.
const UnitPath = "/etc/systemd/system/deplite-agent.service"

var (
	// ErrReplaceDeclined reports that the operator declined replacing the unit.
	ErrReplaceDeclined = errors.New("systemd unit replacement declined")
	// ErrConfirmNeeded reports that replacement needs an interactive answer or --yes.
	ErrConfirmNeeded = errors.New("systemd unit replacement requires confirmation")
)

// Ops contains system interactions so service changes can be tested without systemd.
type Ops interface {
	IsDir(string) bool
	LookPath(string) (string, error)
	ReadFile(string) ([]byte, error)
	Run(context.Context, string, ...string) ([]byte, error)
	WriteFile(string, []byte, os.FileMode) error
	CreateTemp([]byte) (string, func(), error)
	MkdirAll(string, os.FileMode) error
	Chown(string, int, int) error
	Remove(string) error
}

// OSOps implements Ops with operating-system commands and files.
type OSOps struct{}

func (OSOps) IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (OSOps) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (OSOps) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (OSOps) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func (OSOps) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func (OSOps) Chown(path string, uid, gid int) error        { return os.Chown(path, uid, gid) }
func (OSOps) Remove(path string) error                     { return os.Remove(path) }

func (OSOps) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (OSOps) CreateTemp(data []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "deplite-agent.service.*")
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// Config holds the environment and paths used to prepare a system service.
type Config struct {
	GOOS         string
	EUID         int
	UID          int
	GID          int
	User         string
	Executable   string
	DataDir      string
	WorkflowsDir string
	UnitPath     string
	NoService    bool
	Yes          bool
}

// UnitConfig contains values rendered into the systemd unit.
type UnitConfig struct {
	User         string
	Executable   string
	DataDir      string
	WorkflowsDir string
}

// Plan is the validated service change that can be applied after registration.
type Plan struct {
	Enabled      bool
	Reason       string
	Config       Config
	Unit         []byte
	Systemctl    string
	Sudo         string
	UseSudo      bool
	UnitExisting bool
}

// ValidatePath rejects paths systemd cannot safely parse in this unit format.
func ValidatePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("경로는 절대경로여야 합니다: %q", path)
	}
	for _, r := range path {
		if r == ' ' || r == '"' || r == '\\' || r == '%' || unicode.IsControl(r) {
			return fmt.Errorf("systemd 서비스 경로에 사용할 수 없는 문자가 있습니다: %q", path)
		}
	}
	return nil
}

// RenderUnit returns the service unit for cfg.
func RenderUnit(cfg UnitConfig) ([]byte, error) {
	for _, path := range []string{cfg.DataDir, cfg.WorkflowsDir, cfg.Executable} {
		if err := ValidatePath(path); err != nil {
			return nil, err
		}
	}
	if cfg.User == "" || strings.ContainsAny(cfg.User, "\r\n\t ") {
		return nil, fmt.Errorf("systemd 서비스 사용자가 올바르지 않습니다: %q", cfg.User)
	}
	unit := fmt.Sprintf(`[Unit]
Description=Deplite Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%s
Environment=DEPLITE_DATA_DIR=%s
Environment=DEPLITE_WORKFLOWS_DIR=%s
EnvironmentFile=-%s/agent.env
ExecStart=%s start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, cfg.User, cfg.DataDir, cfg.WorkflowsDir, cfg.DataDir, cfg.Executable)
	return []byte(unit), nil
}

// Prepare checks service prerequisites and obtains required sudo authorization.
func Prepare(ctx context.Context, cfg Config, ops Ops, out io.Writer, confirm func(string) bool) (*Plan, error) {
	if cfg.UnitPath == "" {
		cfg.UnitPath = UnitPath
	}
	if cfg.NoService {
		return &Plan{Reason: "--no-service"}, nil
	}
	if cfg.GOOS != "linux" || !ops.IsDir("/run/systemd/system") {
		return &Plan{Reason: "systemd를 사용할 수 없습니다"}, nil
	}
	unit, err := RenderUnit(UnitConfig{
		User: cfg.User, Executable: cfg.Executable,
		DataDir: cfg.DataDir, WorkflowsDir: cfg.WorkflowsDir,
	})
	if err != nil {
		return nil, err
	}
	systemctl, err := ops.LookPath("systemctl")
	if err != nil {
		return nil, fmt.Errorf("systemctl을 찾지 못했습니다: %w", err)
	}
	plan := &Plan{
		Enabled: true, Config: cfg, Unit: unit, Systemctl: systemctl,
		UseSudo: cfg.EUID != 0,
	}
	existing, err := ops.ReadFile(cfg.UnitPath)
	if err == nil {
		plan.UnitExisting = true
		if !bytes.Equal(existing, unit) {
			fmt.Fprintln(out, "기존 서비스 설정과 새 설정이 다릅니다.")
			printExistingUnit(out, existing)
			if !cfg.Yes {
				if confirm == nil {
					return nil, ErrConfirmNeeded
				}
				if !confirm("기존 서비스를 새 설정으로 바꾸시겠습니까?") {
					return nil, ErrReplaceDeclined
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("기존 서비스 설정을 읽지 못했습니다: %w", err)
	}
	if plan.UseSudo {
		plan.Sudo, err = ops.LookPath("sudo")
		if err != nil {
			return nil, fmt.Errorf("sudo를 찾지 못했습니다. `sudo deplite-agent install ...` 또는 `--no-service`를 사용해주세요")
		}
		output, err := ops.Run(ctx, plan.Sudo, "-v")
		if err != nil {
			return nil, fmt.Errorf("sudo 인증에 실패했습니다. `sudo deplite-agent install ...` 또는 `--no-service`를 사용해주세요: %s", errorDetail(output, err))
		}
	}
	return plan, nil
}

// Apply creates the workflow directory, installs the unit, and starts the service.
func (p *Plan) Apply(ctx context.Context, ops Ops, out io.Writer) error {
	if p == nil || !p.Enabled {
		return nil
	}
	fmt.Fprintln(out, "다음 작업을 수행합니다: 워크플로우 디렉토리 생성, systemd 서비스 설치, 서비스 활성화 및 재시작.")
	if err := ops.MkdirAll(p.Config.WorkflowsDir, 0o755); err != nil {
		return fmt.Errorf("워크플로우 디렉토리를 만들지 못했습니다: %w", err)
	}
	if p.Config.EUID == 0 {
		if err := ops.Chown(p.Config.WorkflowsDir, p.Config.UID, p.Config.GID); err != nil {
			return fmt.Errorf("워크플로우 디렉토리 소유자를 설정하지 못했습니다: %w", err)
		}
		if err := ops.WriteFile(p.Config.UnitPath, p.Unit, 0o644); err != nil {
			return fmt.Errorf("서비스 파일을 설치하지 못했습니다: %w", err)
		}
	} else {
		tmp, cleanup, err := ops.CreateTemp(p.Unit)
		if err != nil {
			return fmt.Errorf("임시 서비스 파일을 만들지 못했습니다: %w", err)
		}
		defer cleanup()
		output, err := ops.Run(ctx, p.Sudo, "install", "-m", "0644", tmp, p.Config.UnitPath)
		if err != nil {
			return commandError("서비스 파일을 설치하지 못했습니다", output, err)
		}
	}
	if output, err := p.runSystemctl(ctx, ops, "daemon-reload"); err != nil {
		return commandError("systemd 설정을 다시 읽지 못했습니다", output, err)
	}
	if output, err := p.runSystemctl(ctx, ops, "enable", "deplite-agent"); err != nil {
		return commandError("deplite-agent 서비스를 활성화하지 못했습니다", output, err)
	}
	if output, err := p.runSystemctl(ctx, ops, "restart", "deplite-agent"); err != nil {
		return commandError("deplite-agent 서비스를 다시 시작하지 못했습니다", output, err)
	}
	return nil
}

// Info describes the configured service and its observed active state.
type Info struct {
	UnitPath     string
	User         string
	ExecStart    string
	DataDir      string
	WorkflowsDir string
	Active       bool
	ActiveState  string
}

// Inspect reads the installed unit and asks systemd whether it is active.
func Inspect(ctx context.Context, goos, unitPath string, ops Ops) (*Info, error) {
	if goos != "linux" {
		return nil, nil
	}
	if unitPath == "" {
		unitPath = UnitPath
	}
	body, err := ops.ReadFile(unitPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info := &Info{UnitPath: unitPath, ActiveState: "unknown"}
	parseUnit(body, info)
	if systemctl, err := ops.LookPath("systemctl"); err == nil {
		output, runErr := ops.Run(ctx, systemctl, "is-active", "deplite-agent")
		state := strings.TrimSpace(string(output))
		if state != "" {
			info.ActiveState = state
		} else if runErr == nil {
			info.ActiveState = "active"
		}
		info.Active = info.ActiveState == "active"
	}
	return info, nil
}

// DataDirHint returns guidance when the service and CLI use different data dirs.
func DataDirHint(info *Info, current string) string {
	if info == nil || info.DataDir == "" || current == "" {
		return ""
	}
	serviceDir, err1 := filepath.Abs(info.DataDir)
	currentDir, err2 := filepath.Abs(current)
	if err1 != nil || err2 != nil || filepath.Clean(serviceDir) == filepath.Clean(currentDir) {
		return ""
	}
	return fmt.Sprintf("서비스는 %s를 사용합니다. `--data-dir %s` 또는 서비스 사용자로 다시 확인해주세요", info.DataDir, info.DataDir)
}

// UninstallDataDirHint prevents removing a service while leaving its credentials behind.
func UninstallDataDirHint(info *Info, current, dataDirFlag, dataDirEnv string) string {
	if dataDirFlag != "" || dataDirEnv != "" {
		return ""
	}
	return DataDirHint(info, current)
}

// UninstallPlan is the validated service removal operation.
type UninstallPlan struct {
	UnitPath  string
	Systemctl string
	Sudo      string
	UseSudo   bool
	Exists    bool
}

// PrepareUninstall checks the installed unit and obtains sudo authorization.
func PrepareUninstall(ctx context.Context, goos, unitPath string, euid int, ops Ops) (*UninstallPlan, error) {
	if unitPath == "" {
		unitPath = UnitPath
	}
	plan := &UninstallPlan{UnitPath: unitPath}
	if goos != "linux" {
		return plan, nil
	}
	if _, err := ops.ReadFile(unitPath); errors.Is(err, os.ErrNotExist) {
		return plan, nil
	} else if err != nil {
		return nil, err
	}
	plan.Exists = true
	plan.UseSudo = euid != 0
	plan.Systemctl, _ = ops.LookPath("systemctl")
	if plan.Systemctl == "" {
		return nil, errors.New("systemctl을 찾지 못했습니다")
	}
	if plan.UseSudo {
		var err error
		plan.Sudo, err = ops.LookPath("sudo")
		if err != nil {
			return nil, errors.New("sudo를 찾지 못했습니다")
		}
		if _, err := ops.Run(ctx, plan.Sudo, "-v"); err != nil {
			return nil, fmt.Errorf("sudo 인증에 실패했습니다: %w", err)
		}
	}
	return plan, nil
}

// Apply stops the service, removes its unit, and reloads systemd.
func (p *UninstallPlan) Apply(ctx context.Context, ops Ops) error {
	if p == nil || !p.Exists {
		return nil
	}
	run := func(args ...string) ([]byte, error) {
		name, fullArgs := p.Systemctl, args
		if p.UseSudo {
			name = p.Sudo
			fullArgs = append([]string{"systemctl"}, args...)
		}
		return ops.Run(ctx, name, fullArgs...)
	}
	if output, err := run("disable", "--now", "deplite-agent"); err != nil {
		return commandError("서비스를 중지하지 못했습니다", output, err)
	}
	if p.UseSudo {
		output, err := ops.Run(ctx, p.Sudo, "rm", "-f", p.UnitPath)
		if err != nil {
			return commandError("서비스 파일을 삭제하지 못했습니다", output, err)
		}
	} else if err := ops.Remove(p.UnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("서비스 파일을 삭제하지 못했습니다: %w", err)
	}
	if output, err := run("daemon-reload"); err != nil {
		return commandError("systemd 설정을 다시 읽지 못했습니다", output, err)
	}
	return nil
}

func (p *Plan) runSystemctl(ctx context.Context, ops Ops, args ...string) ([]byte, error) {
	name, fullArgs := p.Systemctl, args
	if p.UseSudo {
		name = p.Sudo
		fullArgs = append([]string{"systemctl"}, args...)
	}
	return ops.Run(ctx, name, fullArgs...)
}

func printExistingUnit(out io.Writer, body []byte) {
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "User=") || strings.HasPrefix(trimmed, "ExecStart=") ||
			strings.HasPrefix(trimmed, "Environment=DEPLITE_DATA_DIR=") ||
			strings.HasPrefix(trimmed, "Environment=DEPLITE_WORKFLOWS_DIR=") {
			fmt.Fprintf(out, "  %s\n", trimmed)
		}
	}
}

func parseUnit(body []byte, info *Info) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "User="):
			info.User = strings.TrimPrefix(line, "User=")
		case strings.HasPrefix(line, "ExecStart="):
			info.ExecStart = strings.TrimPrefix(line, "ExecStart=")
		case strings.HasPrefix(line, "Environment=DEPLITE_DATA_DIR="):
			info.DataDir = strings.TrimPrefix(line, "Environment=DEPLITE_DATA_DIR=")
		case strings.HasPrefix(line, "Environment=DEPLITE_WORKFLOWS_DIR="):
			info.WorkflowsDir = strings.TrimPrefix(line, "Environment=DEPLITE_WORKFLOWS_DIR=")
		}
	}
}

func errorDetail(output []byte, err error) string {
	detail := strings.TrimSpace(string(output))
	if detail == "" && err != nil {
		detail = err.Error()
	}
	return detail
}

func commandError(label string, output []byte, err error) error {
	return fmt.Errorf("%s: %s", label, errorDetail(output, err))
}
