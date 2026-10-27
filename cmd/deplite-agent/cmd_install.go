package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/systemd"
)

func runInstall(args []string) int {
	fs := newFlagSet("install",
		"deplite-agent install [--code <1회용_설치_코드>] [--name NAME] [--base-url URL] [--data-dir DIR] [--workflows-dir DIR] [--no-service] [--yes]",
		"이 머신을 등록하고 systemd 서비스를 설정합니다.")
	code := fs.String("code", "", "1회용 설치 코드 (또는 DEPLITE_INSTALL_CODE)")
	baseURL := fs.String("base-url", "", "백엔드 베이스 URL (기본값: $DEPLITE_BASE_URL 또는 "+defaultBaseURL+")")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	name := fs.String("name", "", "대시보드에 표시할 Agent 이름")
	noService := fs.Bool("no-service", false, "systemd 서비스를 설정하지 않습니다")
	yes := fs.Bool("yes", false, "기존 서비스 설정 교체를 확인 없이 진행합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, wfDir, err := installDirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	deps, err := defaultInstallDeps(*noService, *yes, dir, wfDir)
	if err != nil {
		return errorf("서비스 설정을 준비하지 못했습니다: %v", err)
	}
	installed, plan, err := installMachine(ctx, installOptions{
		BaseURL: resolveBaseURL(*baseURL), DataDir: dir, WorkflowsDir: wfDir,
		InstallCode: resolveInstallCode(*code), Name: *name, Version: version,
		NoService: *noService, Yes: *yes,
	}, deps)
	if err != nil {
		if errors.Is(err, systemd.ErrConfirmNeeded) || errors.Is(err, systemd.ErrReplaceDeclined) {
			return errorf("기존 서비스 설정을 교체하지 않았습니다. --yes 를 지정해 다시 실행할 수 있습니다")
		}
		return errorf("설치에 실패했습니다: %v", err)
	}
	fmt.Printf("설치가 완료되었습니다.\n  agentId:           %s\n  organizationId:    %s\n  데이터 디렉토리:    %s\n  워크플로우 디렉토리: %s\n",
		installed.AgentID, installed.OrganizationID, dir, wfDir)
	fmt.Printf("워크플로우 YAML 파일을 %s 에 넣어주세요.\n", wfDir)
	if plan.Enabled {
		fmt.Println("systemctl status deplite-agent 로 상태를 확인하고, journalctl -u deplite-agent -f 로 로그를 확인해주세요.")
	} else {
		fmt.Println("서비스를 설정하지 않았습니다. deplite-agent start 로 Agent를 실행해주세요.")
	}
	return 0
}

type installOptions struct {
	BaseURL      string
	DataDir      string
	WorkflowsDir string
	InstallCode  string
	Name         string
	Version      string
	NoService    bool
	Yes          bool
}

type installDeps struct {
	ServiceConfig systemd.Config
	ServiceOps    systemd.Ops
	Out           io.Writer
	Confirm       func(string) bool
	Load          func(string) (credstore.Identity, bool, error)
	Register      func(context.Context, agent.InstallOptions) (credstore.Identity, error)
	MkdirAll      func(string, os.FileMode) error
}

func installMachine(ctx context.Context, opts installOptions, deps installDeps) (credstore.Identity, *systemd.Plan, error) {
	id, exists, err := deps.Load(opts.DataDir)
	if err != nil {
		return credstore.Identity{}, nil, fmt.Errorf("자격증명을 읽지 못했습니다: %w", err)
	}
	if exists && opts.InstallCode != "" {
		return credstore.Identity{}, nil, fmt.Errorf("이미 자격증명이 있는 데이터 디렉토리입니다. 코드를 빼고 다시 실행하면 서비스만 설정합니다")
	}
	if !exists && opts.InstallCode == "" {
		return credstore.Identity{}, nil, fmt.Errorf("1회용 설치 코드가 필요합니다 (--code 또는 DEPLITE_INSTALL_CODE)")
	}
	plan, err := systemd.Prepare(ctx, deps.ServiceConfig, deps.ServiceOps, deps.Out, deps.Confirm)
	if err != nil {
		return credstore.Identity{}, nil, err
	}
	if !exists {
		id, err = deps.Register(ctx, agent.InstallOptions{
			BaseURL: opts.BaseURL, DataDir: opts.DataDir,
			InstallCode: opts.InstallCode, Name: opts.Name, Version: opts.Version,
		})
		if err != nil {
			return credstore.Identity{}, nil, fmt.Errorf("등록에 실패했습니다: %w", err)
		}
	} else if plan.Enabled {
		fmt.Fprintln(deps.Out, "이미 등록된 머신입니다. 서비스만 설정합니다.")
	} else {
		fmt.Fprintln(deps.Out, "이미 등록된 머신입니다. 등록은 건너뜁니다.")
	}
	if plan.Enabled {
		if err := plan.Apply(ctx, deps.ServiceOps, deps.Out); err != nil {
			return credstore.Identity{}, plan, err
		}
	} else {
		if err := deps.MkdirAll(opts.WorkflowsDir, 0o755); err != nil {
			return credstore.Identity{}, plan, fmt.Errorf("워크플로우 디렉토리를 만들지 못했습니다: %w", err)
		}
		if plan.Reason == "--no-service" {
			fmt.Fprintln(deps.Out, "--no-service 를 지정해 서비스를 설정하지 않습니다.")
		} else {
			fmt.Fprintln(deps.Out, "systemd를 사용할 수 없어 서비스를 설정하지 않습니다.")
		}
	}
	return id, plan, nil
}

func installDirs(dataDirFlag, workflowsDirFlag string) (string, string, error) {
	dataDir, err := resolveDataDir(dataDirFlag)
	if err != nil {
		return "", "", err
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return "", "", err
	}
	workflowsDir := resolveWorkflowsDir(workflowsDirFlag, dataDir)
	workflowsDir, err = filepath.Abs(workflowsDir)
	if err != nil {
		return "", "", err
	}
	return filepath.Clean(dataDir), filepath.Clean(workflowsDir), nil
}

func defaultInstallDeps(noService, yes bool, dataDir, workflowsDir string) (installDeps, error) {
	ops := systemd.OSOps{}
	cfg := systemd.Config{
		GOOS: runtime.GOOS, EUID: os.Geteuid(), UID: os.Geteuid(), GID: os.Getegid(),
		DataDir: dataDir, WorkflowsDir: workflowsDir, UnitPath: systemd.UnitPath,
		NoService: noService, Yes: yes,
	}
	if !noService && runtime.GOOS == "linux" && ops.IsDir("/run/systemd/system") {
		current, err := user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			return installDeps{}, fmt.Errorf("서비스 사용자를 확인하지 못했습니다: %w", err)
		}
		uid, err := strconv.Atoi(current.Uid)
		if err != nil {
			return installDeps{}, fmt.Errorf("서비스 사용자 ID가 올바르지 않습니다: %w", err)
		}
		gid, err := strconv.Atoi(current.Gid)
		if err != nil {
			return installDeps{}, fmt.Errorf("서비스 그룹 ID가 올바르지 않습니다: %w", err)
		}
		executable, err := os.Executable()
		if err != nil {
			return installDeps{}, fmt.Errorf("실행 파일 경로를 확인하지 못했습니다: %w", err)
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return installDeps{}, fmt.Errorf("실행 파일 실제 경로를 확인하지 못했습니다: %w", err)
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			return installDeps{}, fmt.Errorf("실행 파일 절대경로를 확인하지 못했습니다: %w", err)
		}
		cfg.User, cfg.UID, cfg.GID, cfg.Executable = current.Username, uid, gid, executable
	}
	return installDeps{
		ServiceConfig: cfg, ServiceOps: ops, Out: os.Stdout, Confirm: confirm,
		Load: func(dir string) (credstore.Identity, bool, error) {
			store := credstore.New(dir)
			if !store.Exists() {
				return credstore.Identity{}, false, nil
			}
			id, _, err := store.Load()
			return id, err == nil, err
		},
		Register: agent.Install,
		MkdirAll: os.MkdirAll,
	}, nil
}

func runUninstall(args []string) int {
	fs := newFlagSet("uninstall",
		"deplite-agent uninstall [--data-dir DIR] [--keep-logs] [--yes]",
		"systemd 서비스와 이 머신의 자격증명·로컬 상태를 지웁니다. 대시보드의 Agent 등록은 남습니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	keepLogs := fs.Bool("keep-logs", false, "작업 로그는 남겨둡니다")
	yes := fs.Bool("yes", false, "확인 없이 진행합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, err := resolveDataDir(*dataDir)
	if err != nil {
		return errorf("%v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serviceInfo, err := systemd.Inspect(ctx, runtime.GOOS, systemd.UnitPath, systemd.OSOps{})
	if err != nil {
		return errorf("서비스 설정을 읽지 못했습니다: %v", err)
	}
	if hint := systemd.UninstallDataDirHint(serviceInfo, dir, *dataDir, os.Getenv("DEPLITE_DATA_DIR")); hint != "" {
		return errorf("%s", hint)
	}
	servicePlan, err := systemd.PrepareUninstall(ctx, runtime.GOOS, systemd.UnitPath, os.Geteuid(), systemd.OSOps{})
	if err != nil {
		return errorf("서비스 제거를 준비하지 못했습니다: %v", err)
	}

	targets := []string{
		filepath.Join(dir, "identity.json"),
		filepath.Join(dir, "agent.key"),
		filepath.Join(dir, "agent.id"),
		filepath.Join(dir, "server.pub"),
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "apps.json"),
		filepath.Join(dir, "limits"),
	}
	if !*keepLogs {
		targets = append(targets, agent.ResolveLogDir(dir))
	}
	var existing []string
	for _, t := range targets {
		if _, err := os.Stat(t); err == nil {
			existing = append(existing, t)
		}
	}
	if servicePlan.Exists {
		existing = append(existing, servicePlan.UnitPath)
	}
	if len(existing) == 0 && !servicePlan.Exists {
		fmt.Println("지울 것이 없습니다.")
		return 0
	}
	if !servicePlan.Exists {
		if st, err := agent.ReadRunState(dir); err == nil && st.Alive() {
			return errorf("pid %d 로 Agent가 실행 중입니다. 먼저 종료한 뒤 다시 시도해주세요", st.PID)
		}
	}

	fmt.Println("아래 경로를 삭제합니다.")
	for _, t := range existing {
		fmt.Println("  " + t)
	}
	if !*yes && !confirm("계속하시겠습니까?") {
		fmt.Println("취소했습니다.")
		return 1
	}
	if servicePlan.Exists {
		if err := servicePlan.Apply(ctx, systemd.OSOps{}); err != nil {
			return errorf("systemd 서비스를 제거하지 못했습니다: %v", err)
		}
		if st, err := agent.ReadRunState(dir); err == nil && st.Alive() {
			return errorf("pid %d 로 Agent가 실행 중입니다. 먼저 종료한 뒤 다시 시도해주세요", st.PID)
		}
	}

	failed := 0
	for _, t := range existing {
		if err := os.RemoveAll(t); err != nil {
			fmt.Fprintf(os.Stderr, "삭제 실패 %s: %v\n", t, err)
			failed++
		}
	}
	if failed > 0 {
		return 1
	}
	fmt.Println("\n삭제했습니다. 대시보드에 남아 있는 Agent 등록은 대시보드에서 직접 삭제해주세요.")
	return 0
}

// confirm asks for an explicit y before a destructive step. A
// non-interactive stdin answers no, so a script has to pass --yes.
func confirm(question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
