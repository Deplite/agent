package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/systemd"
	"github.com/Deplite/agent/internal/update"
)

type updateCmdDeps struct {
	Out             io.Writer
	Err             io.Writer
	CurrentVersion  string
	GOOS            string
	GOARCH          string
	Executable      func() (string, error)
	EvalSymlinks    func(string) (string, error)
	CanWriteDir     func(string) bool
	MarkerPath      string
	MarkerExists    func(string) bool
	IsTerminal      func() bool
	Ask             func(string) bool
	InspectService  func(context.Context) (*systemd.Info, error)
	SystemdOps      systemd.Ops
	ReadRunState    func(string) (agent.RunState, error)
	Alive           func(agent.RunState) bool
	DataDirs        func() (string, error)
	LookPath        func(string) (string, error)
	RunCommand      func(context.Context, string, ...string) ([]byte, error)
	Latest          func(context.Context, update.Options) (update.Version, error)
	Download        func(context.Context, update.Version, string, string, string, update.Options) (string, error)
	StageBinary     func(string, string) (string, func(), error)
	VerifyBinary    func(string, string) error
	ReplaceBinary   func(string, string) error
	Now             func() time.Time
	Sleep           func(time.Duration)
	ReleaseBaseURL  string
	HTTPClient      *http.Client
	EffectiveUserID func() int
}

func defaultUpdateCmdDeps() updateCmdDeps {
	return updateCmdDeps{
		Out: os.Stdout, Err: os.Stderr, CurrentVersion: version,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Executable: os.Executable, EvalSymlinks: filepath.EvalSymlinks,
		CanWriteDir: canWriteDirectory, MarkerPath: "/.dockerenv",
		MarkerExists: func(path string) bool { _, err := os.Stat(path); return err == nil },
		IsTerminal: func() bool {
			info, err := os.Stdin.Stat()
			return err == nil && info.Mode()&os.ModeCharDevice != 0
		},
		Ask: func(question string) bool {
			fmt.Fprintf(os.Stdout, "%s [y/N]: ", question)
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return false
			}
			answer := strings.ToLower(strings.TrimSpace(line))
			return answer == "y" || answer == "yes"
		},
		InspectService: func(ctx context.Context) (*systemd.Info, error) {
			return systemd.Inspect(ctx, runtime.GOOS, systemd.UnitPath, systemd.OSOps{})
		},
		SystemdOps: systemd.OSOps{}, ReadRunState: agent.ReadRunState,
		Alive: func(state agent.RunState) bool { return state.Alive() },
		DataDirs: func() (string, error) {
			dir, _, err := dirs("", "")
			return dir, err
		},
		LookPath: exec.LookPath,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		Latest: update.Latest, Download: update.Download,
		StageBinary: update.StageBinary, VerifyBinary: verifyUpdateBinary,
		ReplaceBinary: update.Replace,
		Now:           time.Now, Sleep: time.Sleep,
		ReleaseBaseURL:  update.RepositoryURL,
		EffectiveUserID: os.Geteuid,
	}
}

func completeUpdateCmdDeps(deps updateCmdDeps) updateCmdDeps {
	defaults := defaultUpdateCmdDeps()
	if deps.Out == nil {
		deps.Out = defaults.Out
	}
	if deps.Err == nil {
		deps.Err = defaults.Err
	}
	if deps.CurrentVersion == "" {
		deps.CurrentVersion = defaults.CurrentVersion
	}
	if deps.GOOS == "" {
		deps.GOOS = defaults.GOOS
	}
	if deps.GOARCH == "" {
		deps.GOARCH = defaults.GOARCH
	}
	if deps.Executable == nil {
		deps.Executable = defaults.Executable
	}
	if deps.EvalSymlinks == nil {
		deps.EvalSymlinks = defaults.EvalSymlinks
	}
	if deps.CanWriteDir == nil {
		deps.CanWriteDir = defaults.CanWriteDir
	}
	if deps.MarkerPath == "" {
		deps.MarkerPath = defaults.MarkerPath
	}
	if deps.MarkerExists == nil {
		deps.MarkerExists = defaults.MarkerExists
	}
	if deps.IsTerminal == nil {
		deps.IsTerminal = defaults.IsTerminal
	}
	if deps.Ask == nil {
		deps.Ask = defaults.Ask
	}
	if deps.InspectService == nil {
		deps.InspectService = defaults.InspectService
	}
	if deps.SystemdOps == nil {
		deps.SystemdOps = defaults.SystemdOps
	}
	if deps.ReadRunState == nil {
		deps.ReadRunState = defaults.ReadRunState
	}
	if deps.Alive == nil {
		deps.Alive = defaults.Alive
	}
	if deps.DataDirs == nil {
		deps.DataDirs = defaults.DataDirs
	}
	if deps.LookPath == nil {
		deps.LookPath = defaults.LookPath
	}
	if deps.RunCommand == nil {
		deps.RunCommand = defaults.RunCommand
	}
	if deps.Latest == nil {
		deps.Latest = defaults.Latest
	}
	if deps.Download == nil {
		deps.Download = defaults.Download
	}
	if deps.StageBinary == nil {
		deps.StageBinary = defaults.StageBinary
	}
	if deps.VerifyBinary == nil {
		deps.VerifyBinary = defaults.VerifyBinary
	}
	if deps.ReplaceBinary == nil {
		deps.ReplaceBinary = defaults.ReplaceBinary
	}
	if deps.Now == nil {
		deps.Now = defaults.Now
	}
	if deps.Sleep == nil {
		deps.Sleep = defaults.Sleep
	}
	if deps.ReleaseBaseURL == "" {
		deps.ReleaseBaseURL = defaults.ReleaseBaseURL
	}
	if deps.EffectiveUserID == nil {
		deps.EffectiveUserID = defaults.EffectiveUserID
	}
	return deps
}

func runUpdate(args []string) int { return runUpdateWithDeps(args, defaultUpdateCmdDeps()) }

func runUpdateWithDeps(args []string, deps updateCmdDeps) int {
	deps = completeUpdateCmdDeps(deps)
	fs := newFlagSet("update", "deplite-agent update [--check] [--version X.Y.Z|vX.Y.Z] [--force] [--yes] [--skip-signature]",
		"GitHub Releases에서 새 Agent 버전을 확인하고 설치합니다.")
	fs.SetOutput(deps.Err)
	check := fs.Bool("check", false, "현재 버전과 최신 버전만 확인합니다")
	versionFlag := fs.String("version", "", "설치할 릴리스 버전 (예: 0.1.0 또는 v0.1.0)")
	force := fs.Bool("force", false, "실행 중인 job이 끝나길 기다리지 않습니다")
	yes := fs.Bool("yes", false, "다운그레이드 확인을 생략합니다")
	skipSignature := fs.Bool("skip-signature", false, "cosign 서명 검증을 건너뜁니다 (checksum은 계속 확인합니다)")
	if _, ok := parseArgs(fs, args, 0); !ok {
		return 2
	}
	if *check && *versionFlag != "" {
		return updateError(deps, "--check와 --version은 함께 사용할 수 없습니다")
	}

	current, currentErr := update.ParseCurrent(deps.CurrentVersion)
	var target update.Version
	if *versionFlag != "" {
		parsed, err := update.ParseVersionInput(*versionFlag)
		if err != nil {
			return updateError(deps, "%v", err)
		}
		target = parsed
	} else {
		var err error
		target, err = deps.Latest(context.Background(), releaseOptions(deps, *skipSignature))
		if err != nil {
			return updateError(deps, "%v", err)
		}
	}
	if *check {
		if currentErr == nil && update.Compare(current, target) >= 0 {
			fmt.Fprintf(deps.Out, "최신 버전입니다 (%s)\n", current.Text)
		} else {
			currentText := deps.CurrentVersion
			fmt.Fprintf(deps.Out, "새 버전이 있습니다: %s → %s\n", currentText, target.Text)
			fmt.Fprintln(deps.Out, "sudo deplite-agent update 로 업데이트할 수 있습니다")
		}
		return 0
	}

	if currentErr != nil {
		fmt.Fprintf(deps.Out, "현재 버전을 알 수 없어(%s) 릴리스 버전(%s)으로 바꿉니다\n", deps.CurrentVersion, target.Text)
	} else {
		comparison := update.Compare(target, current)
		if comparison == 0 {
			fmt.Fprintf(deps.Out, "이미 %s입니다\n", target.Text)
			return 0
		}
		if comparison < 0 {
			if !*yes {
				if !deps.IsTerminal() {
					return updateError(deps, "다운그레이드는 터미널에서 확인하거나 --yes를 지정해야 합니다")
				}
				if !deps.Ask(fmt.Sprintf("현재 버전(%s)보다 낮은 버전(%s)으로 다운그레이드할까요?", current.Text, target.Text)) {
					fmt.Fprintln(deps.Out, "취소했습니다.")
					return 1
				}
			}
		}
	}

	if deps.MarkerExists(deps.MarkerPath) {
		return updateError(deps, "컨테이너 안에서는 업데이트할 수 없습니다. 이미지를 새 버전으로 바꿔주세요")
	}
	executable, err := deps.Executable()
	if err != nil {
		return updateError(deps, "실행 파일 경로를 확인하지 못했습니다: %v", err)
	}
	targetPath, err := deps.EvalSymlinks(executable)
	if err != nil {
		return updateError(deps, "실행 파일 경로를 확인하지 못했습니다: %v", err)
	}
	targetPath = filepath.Clean(targetPath)
	service, err := deps.InspectService(context.Background())
	if err != nil {
		return updateError(deps, "서비스 설정을 읽지 못했습니다: %v", err)
	}
	if service != nil && service.ExecStart != "" {
		serviceExec := execStartPath(service.ExecStart)
		serviceTarget, evalErr := deps.EvalSymlinks(serviceExec)
		if evalErr != nil {
			serviceTarget = serviceExec
		}
		if filepath.Clean(serviceTarget) != targetPath {
			return updateError(deps, "서비스 실행 파일: %s. 이 경로로 실행해주세요: sudo %s update", serviceExec, serviceExec)
		}
	}
	if !deps.CanWriteDir(filepath.Dir(targetPath)) {
		return updateError(deps, "권한이 없습니다. sudo deplite-agent update로 실행해주세요")
	}
	fmt.Fprintf(deps.Out, "대상: %s\n%s → %s\n", targetPath, deps.CurrentVersion, target.Text)

	tempDir, err := os.MkdirTemp("", "deplite-agent-update-*")
	if err != nil {
		return updateError(deps, "임시 디렉토리를 만들지 못했습니다: %v", err)
	}
	defer os.RemoveAll(tempDir)
	options := releaseOptions(deps, *skipSignature)
	archive, err := deps.Download(context.Background(), target, deps.GOOS, deps.GOARCH, tempDir, options)
	if err != nil {
		return updateError(deps, "%v", err)
	}
	binary := filepath.Join(tempDir, "deplite-agent")
	if err := update.ExtractBinary(archive, binary); err != nil {
		return updateError(deps, "실행 파일을 압축 해제하지 못했습니다: %v", err)
	}
	staged, cleanup, err := deps.StageBinary(targetPath, binary)
	if err != nil {
		return updateError(deps, "새 실행 파일을 준비하지 못했습니다: %v", err)
	}
	defer cleanup()
	if err := deps.VerifyBinary(staged, target.Text); err != nil {
		return updateError(deps, "새 실행 파일 자체 점검에 실패했습니다: %v", err)
	}

	dataDir := ""
	if service != nil && service.DataDir != "" {
		dataDir = service.DataDir
	} else {
		dataDir, err = deps.DataDirs()
		if err != nil {
			return updateError(deps, "데이터 디렉토리를 결정하지 못했습니다: %v", err)
		}
	}
	before, beforeErr := deps.ReadRunState(dataDir)
	oldPID := 0
	if beforeErr == nil {
		oldPID = before.PID
	}
	if service != nil && service.Active && !*force {
		if err := waitForJob(deps, dataDir); err != nil {
			return updateError(deps, "%v", err)
		}
	}
	if err := deps.ReplaceBinary(targetPath, staged); err != nil {
		return updateError(deps, "실행 파일을 교체하지 못했습니다: %v", err)
	}
	if service != nil && service.Active {
		if output, restartErr := restartService(deps); restartErr != nil {
			return restartFailure(deps, targetPath, output, restartErr)
		}
		if err := waitForRestart(deps, dataDir, oldPID, target.Text); err != nil {
			return restartFailure(deps, targetPath, nil, err)
		}
		fmt.Fprintf(deps.Out, "deplite-agent를 새 버전(%s)으로 다시 시작했습니다\n", target.Text)
		return 0
	}
	fmt.Fprintf(deps.Out, "다음 시작부터 새 버전(%s)이 적용됩니다\n", target.Text)
	if state, stateErr := deps.ReadRunState(dataDir); stateErr == nil && deps.Alive(state) {
		fmt.Fprintln(deps.Out, "실행 중인 agent를 다시 시작해주세요")
	}
	return 0
}

func releaseOptions(deps updateCmdDeps, skipSignature bool) update.Options {
	return update.Options{
		BaseURL: deps.ReleaseBaseURL, HTTPClient: deps.HTTPClient,
		UserAgent: "deplite-agent/" + deps.CurrentVersion,
		LookPath:  deps.LookPath, RunCommand: deps.RunCommand,
		SkipSignature: skipSignature, Out: deps.Out,
	}
}

func canWriteDirectory(dir string) bool {
	file, err := os.CreateTemp(dir, ".deplite-agent-update-probe-*")
	if err != nil {
		return false
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return false
	}
	return os.Remove(name) == nil
}

func verifyUpdateBinary(path, expected string) error {
	return verifyUpdateBinaryWithTimeout(path, expected, 30*time.Second)
}

func verifyUpdateBinaryWithTimeout(path, expected string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	prefix := "deplite-agent " + expected + " "
	if err != nil {
		return fmt.Errorf("version 실행 실패: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	if !strings.HasPrefix(string(output), prefix) {
		return fmt.Errorf("version 출력이 예상과 다릅니다: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func execStartPath(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], `"'`)
}

func waitForJob(deps updateCmdDeps, dataDir string) error {
	state, err := deps.ReadRunState(dataDir)
	if err != nil || !deps.Alive(state) || state.CurrentJobID == "" {
		return nil
	}
	fmt.Fprintf(deps.Out, "실행 중인 job의 종료를 기다립니다 (workflow: %s, job ID: %s)\n", state.CurrentWorkflow, state.CurrentJobID)
	deadline := deps.Now().Add(10 * time.Minute)
	for deps.Now().Before(deadline) {
		remaining := deadline.Sub(deps.Now())
		pause := 2 * time.Second
		if remaining < pause {
			pause = remaining
		}
		deps.Sleep(pause)
		state, err = deps.ReadRunState(dataDir)
		if err != nil || !deps.Alive(state) || state.CurrentJobID == "" {
			return nil
		}
	}
	return errors.New("실행 중인 job이 10분 안에 끝나지 않았습니다. --force로 대기를 건너뛸 수 있습니다")
}

func restartService(deps updateCmdDeps) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	systemctl, err := deps.SystemdOps.LookPath("systemctl")
	if err != nil {
		return nil, fmt.Errorf("systemctl을 찾지 못했습니다: %w", err)
	}
	if deps.EffectiveUserID() == 0 {
		return deps.SystemdOps.Run(ctx, systemctl, "restart", "deplite-agent")
	}
	sudo, err := deps.SystemdOps.LookPath("sudo")
	if err != nil {
		return nil, errors.New("sudo를 찾지 못했습니다")
	}
	return deps.SystemdOps.Run(ctx, sudo, "systemctl", "restart", "deplite-agent")
}

func waitForRestart(deps updateCmdDeps, dataDir string, oldPID int, expected string) error {
	deadline := deps.Now().Add(60 * time.Second)
	for {
		state, err := deps.ReadRunState(dataDir)
		if err == nil && state.PID > 0 && state.PID != oldPID && deps.Alive(state) && state.Version == expected {
			return nil
		}
		if !deps.Now().Before(deadline) {
			return errors.New("60초 안에 새 프로세스의 실행 상태와 버전을 확인하지 못했습니다")
		}
		pause := 2 * time.Second
		if remaining := deadline.Sub(deps.Now()); remaining < pause {
			pause = remaining
		}
		deps.Sleep(pause)
	}
}

func restartFailure(deps updateCmdDeps, target string, output []byte, err error) int {
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		detail = err.Error()
	}
	fmt.Fprintf(deps.Err, "오류: 서비스를 새 버전으로 다시 시작하지 못했습니다: %s\n", detail)
	fmt.Fprintf(deps.Err, "롤백: sudo mv %s.prev %s && sudo systemctl restart deplite-agent\n", shellQuote(target), shellQuote(target))
	fmt.Fprintln(deps.Err, "상태 확인: sudo journalctl -u deplite-agent -n 100 --no-pager")
	return 1
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func updateError(deps updateCmdDeps, format string, args ...any) int {
	fmt.Fprintf(deps.Err, "오류: "+format+"\n", args...)
	return 1
}
