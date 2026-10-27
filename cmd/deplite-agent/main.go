// Command deplite-agent is the entry point for the Deplite Agent.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Deplite/agent/internal/alog"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const defaultBaseURL = "https://api.deplite.io/v1"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	// Only the long-lived daemon logs at info; the one-shot commands
	// print their own output and would otherwise interleave it with
	// operator logs on stderr.
	level := slog.LevelWarn
	if os.Args[1] == "start" {
		level = slog.LevelInfo
	}
	slog.SetDefault(alog.Init(resolveLogPath(), level))

	args := os.Args[2:]
	switch os.Args[1] {
	case "install":
		os.Exit(runInstall(args))
	case "uninstall":
		os.Exit(runUninstall(args))
	case "start":
		os.Exit(runStart(args))
	case "validate":
		os.Exit(runValidate(args))
	case "list":
		os.Exit(runList(args))
	case "run":
		os.Exit(runRun(args))
	case "status":
		os.Exit(runStatus(args))
	case "doctor":
		os.Exit(runDoctor(args))
	case "logs":
		os.Exit(runLogs(args))
	case "limits":
		os.Exit(runLimits(args))
	case "version", "-v", "--version":
		fmt.Printf("deplite-agent %s (commit %s, built %s)\n", version, commit, date)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "알 수 없는 명령입니다: %s\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

// newFlagSet builds a subcommand parser whose help starts with a one-line
// synopsis, so `deplite-agent run --help` reads like a man page entry.
func newFlagSet(name, synopsis, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "%s\n\n사용법:\n  %s\n\n옵션:\n", summary, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseOneArg parses flags around a single positional argument. Go's
// flag package stops at the first bare word, so the tail is parsed again
// once that word is taken out and `run hello --param k=v` works.
func parseOneArg(fs *flag.FlagSet, args []string) (string, bool) {
	if err := fs.Parse(args); err != nil {
		return "", false
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return "", false
	}
	name := rest[0]
	if len(rest) > 1 {
		if err := fs.Parse(rest[1:]); err != nil {
			return "", false
		}
		if fs.NArg() > 0 {
			fmt.Fprintf(os.Stderr, "오류: 인자가 너무 많습니다: %s\n", strings.Join(fs.Args(), " "))
			return "", false
		}
	}
	return name, true
}

// stringList collects a flag that may be repeated, such as --param.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func errorf(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "오류: "+format+"\n", args...)
	return 1
}

func resolveInstallCode(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("DEPLITE_INSTALL_CODE"); v != "" {
		return v
	}
	for _, legacy := range []string{"DEPLITE_TOKEN", "DEPLITE_ENROLLMENT_TOKEN"} {
		if v := os.Getenv(legacy); v != "" {
			fmt.Fprintf(os.Stderr, "경고: %s 는 더 이상 사용되지 않습니다. DEPLITE_INSTALL_CODE 를 사용해주세요\n", legacy)
			return v
		}
	}
	return ""
}

func resolveBaseURL(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("DEPLITE_BASE_URL"); v != "" {
		return v
	}
	return defaultBaseURL
}

// resolveLogPath returns the path for the rotated agent.log. Empty
// means file logging is disabled and only stderr is used.
func resolveLogPath() string {
	if v := os.Getenv("DEPLITE_LOG_DIR"); v != "" {
		return filepath.Join(v, "agent.log")
	}
	return ""
}

func resolveDataDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv("DEPLITE_DATA_DIR"); v != "" {
		return v, nil
	}
	return defaultDataDir()
}

func defaultDataDir() (string, error) {
	home, err := effectiveHomeDir()
	if err != nil {
		return "", fmt.Errorf("데이터 디렉토리를 결정하지 못했습니다: %w", err)
	}
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() == 0 {
			// Use root's passwd home so sudo preserving HOME cannot split registration paths.
			return filepath.Join(home, ".config", "deplite-agent"), nil
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome != "" {
			if !filepath.IsAbs(configHome) {
				return "", fmt.Errorf("XDG_CONFIG_HOME 은 절대경로여야 합니다")
			}
			return filepath.Join(configHome, "deplite-agent"), nil
		}
		return filepath.Join(home, ".config", "deplite-agent"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "deplite-agent"), nil
	default:
		config, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("데이터 디렉토리를 결정하지 못했습니다: %w", err)
		}
		return filepath.Join(config, "deplite-agent"), nil
	}
}

func effectiveHomeDir() (string, error) {
	current, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err == nil && current.HomeDir != "" {
		return current.HomeDir, nil
	}
	home, homeErr := os.UserHomeDir()
	if homeErr == nil && home != "" {
		return home, nil
	}
	if err != nil {
		return "", err
	}
	return "", homeErr
}

func resolveWorkflowsDir(flagVal, dataDir string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("DEPLITE_WORKFLOWS_DIR"); v != "" {
		return v
	}
	return filepath.Join(dataDir, "workflows")
}

// dirs resolves the two directories nearly every subcommand needs.
func dirs(dataDirFlag, workflowsDirFlag string) (dataDir, workflowsDir string, err error) {
	dataDir, err = resolveDataDir(dataDirFlag)
	if err != nil {
		return "", "", err
	}
	return dataDir, resolveWorkflowsDir(workflowsDirFlag, dataDir), nil
}

func usage(w *os.File) {
	fmt.Fprintf(w, `Deplite Agent

사용법:
  deplite-agent <명령> [옵션]

설치와 실행
  install     이 머신을 등록하고 systemd 서비스를 설정합니다
  start       Agent를 실행해 대시보드가 보내는 작업을 처리합니다
  uninstall   systemd 서비스와 이 머신의 자격증명·로컬 상태를 지웁니다

워크플로우
  validate    워크플로우 파일을 검사합니다
  list        Agent가 인식한 워크플로우를 보여줍니다
  run         워크플로우를 이 머신에서 바로 실행합니다

진단
  status      등록 정보와 실행 상태를 보여줍니다
  doctor      설치·연결·권한을 한 번에 점검합니다
  logs        지난 작업의 로그를 봅니다
  limits      워크플로우 실행 제한 상태를 보거나 초기화합니다

기타
  version     버전을 출력합니다
  help        이 도움말을 출력합니다

명령별 옵션은 deplite-agent <명령> --help 로 확인하실 수 있습니다.

환경변수
  DEPLITE_INSTALL_CODE   1회용 설치 코드
  DEPLITE_BASE_URL       백엔드 베이스 URL (기본값 %s)
  DEPLITE_DATA_DIR       데이터 디렉토리
  DEPLITE_WORKFLOWS_DIR  워크플로우 디렉토리
  DEPLITE_SECRET_<KEY>   워크플로우 secrets 에 선언된 키의 값
`, defaultBaseURL)
}
