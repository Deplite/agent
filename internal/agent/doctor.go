package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/runner"
	"github.com/Deplite/agent/internal/systemd"
	"github.com/Deplite/agent/internal/workflow"
)

type CheckResult string

const (
	CheckOK   CheckResult = "OK"
	CheckWarn CheckResult = "WARN"
	CheckFail CheckResult = "FAIL"
)

// Check is one self-diagnosis line. Detail is written for the operator
// reading the terminal, so it is Korean like the rest of the CLI surface.
type Check struct {
	Name   string
	Result CheckResult
	Detail string
}

type DoctorOptions struct {
	DataDir      string
	WorkflowsDir string
	Timeout      time.Duration
}

// Doctor runs every self-check in order and returns what it found. The
// only thing it changes anywhere is the heartbeat it sends to prove the
// credentials still work.
func Doctor(ctx context.Context, opts DoctorOptions) []Check {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	checks := []Check{checkDataDir(opts.DataDir)}

	store := credstore.New(opts.DataDir)
	var id credstore.Identity
	credOK := false
	if !store.Exists() {
		checks = append(checks, check("자격증명", CheckFail,
			"등록되지 않았습니다. `deplite-agent install --code <1회용_설치_코드>` 를 먼저 실행해주세요"))
	} else if loaded, _, err := store.Load(); err != nil {
		checks = append(checks, check("자격증명", CheckFail, "읽을 수 없습니다: %v", err))
	} else {
		id, credOK = loaded, true
		checks = append(checks, check("자격증명", CheckOK,
			"agentId=%s organizationId=%s", loaded.AgentID, loaded.OrganizationID))
	}

	checks = append(checks, checkKeyPerm(opts.DataDir))
	if credOK {
		checks = append(checks, checkBackend(ctx, opts.DataDir, id, timeout))
	} else {
		checks = append(checks, check("백엔드 연결", CheckWarn, "자격증명이 없어 건너뛰었습니다"))
	}

	return append(checks,
		checkWorkflows(opts.WorkflowsDir),
		checkShell(),
		checkService(opts.DataDir),
		checkLogDir(opts.DataDir),
		checkRunning(opts.DataDir),
	)
}

func checkService(dataDir string) Check {
	info, err := systemd.Inspect(context.Background(), runtime.GOOS, systemd.UnitPath, systemd.OSOps{})
	return serviceCheck(runtime.GOOS, info, err, dataDir)
}

func serviceCheck(goos string, info *systemd.Info, err error, dataDir string) Check {
	if goos != "linux" {
		return check("서비스", CheckOK, "systemd 서비스를 사용하지 않는 플랫폼입니다. deplite-agent start로 실행해주세요")
	}
	if err != nil {
		return check("서비스", CheckFail, "서비스 설정을 읽지 못했습니다: %v", err)
	}
	if info == nil {
		return check("서비스", CheckWarn, "systemd 서비스가 설정되어 있지 않습니다")
	}
	result := CheckOK
	if !info.Active {
		result = CheckWarn
	}
	detail := fmt.Sprintf("%s, User=%s, 상태=%s, 데이터 디렉토리=%s",
		info.UnitPath, info.User, info.ActiveState, info.DataDir)
	if hint := systemd.DataDirHint(info, dataDir); hint != "" {
		detail += ". " + hint
	}
	return check("서비스", result, "%s", detail)
}

func check(name string, res CheckResult, format string, args ...any) Check {
	return Check{Name: name, Result: res, Detail: fmt.Sprintf(format, args...)}
}

func checkDataDir(dir string) Check {
	fi, err := os.Stat(dir)
	if err != nil {
		return check("데이터 디렉토리", CheckFail, "%s 를 열 수 없습니다: %v", dir, err)
	}
	if !fi.IsDir() {
		return check("데이터 디렉토리", CheckFail, "%s 가 디렉토리가 아닙니다", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return check("데이터 디렉토리", CheckWarn, "%s 권한이 %04o 입니다. 0700 을 권장합니다", dir, perm)
	}
	return check("데이터 디렉토리", CheckOK, "%s", dir)
}

func checkKeyPerm(dir string) Check {
	path := filepath.Join(dir, "agent.key")
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return check("개인키 권한", CheckWarn, "아직 키가 없습니다")
	}
	if err != nil {
		return check("개인키 권한", CheckFail, "%v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return check("개인키 권한", CheckFail, "%s 권한이 %04o 입니다. `chmod 600` 으로 좁혀주세요", path, perm)
	}
	return check("개인키 권한", CheckOK, "0600")
}

func checkBackend(ctx context.Context, dataDir string, id credstore.Identity, timeout time.Duration) Check {
	_, kp, err := credstore.New(dataDir).Load()
	if err != nil {
		return check("백엔드 연결", CheckFail, "%v", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	if err := apiclient.New(id.BaseURL).Heartbeat(reqCtx, newSigner(id.AgentID, kp)); err != nil {
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
			return check("백엔드 연결", CheckFail,
				"%s 가 이 Agent의 자격증명을 거부했습니다 (HTTP %d). 대시보드에서 삭제된 Agent라면 다시 설치해주세요",
				id.BaseURL, apiErr.StatusCode)
		}
		return check("백엔드 연결", CheckFail, "%s 에 연결하지 못했습니다: %v", id.BaseURL, err)
	}
	return check("백엔드 연결", CheckOK, "%s (%dms)", id.BaseURL, time.Since(started).Milliseconds())
}

func checkWorkflows(dir string) Check {
	if _, err := os.Stat(dir); err != nil {
		return check("워크플로우 디렉토리", CheckWarn,
			"%s 가 없습니다. 워크플로우를 쓰지 않는 호스트라면 정상입니다", dir)
	}
	wfs, bad := workflow.Scan(dir)
	if len(bad) > 0 {
		return check("워크플로우 디렉토리", CheckFail,
			"정상 %d개, 오류 %d개. `deplite-agent validate` 로 확인해주세요", len(wfs), len(bad))
	}
	return check("워크플로우 디렉토리", CheckOK, "%s (%d개)", dir, len(wfs))
}

func checkShell() Check {
	shell := runner.DefaultShell()
	path, err := exec.LookPath(shell)
	if err != nil {
		return check("스텝 셸", CheckFail, "%s 를 찾을 수 없습니다: %v", shell, err)
	}
	return check("스텝 셸", CheckOK, "%s", path)
}

func checkLogDir(dataDir string) Check {
	dir := resolveLogDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return check("로그 디렉토리", CheckFail, "%s 를 만들 수 없습니다: %v", dir, err)
	}
	probe := filepath.Join(dir, ".doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return check("로그 디렉토리", CheckFail, "%s 에 쓸 수 없습니다: %v", dir, err)
	}
	_ = os.Remove(probe)
	return check("로그 디렉토리", CheckOK, "%s", dir)
}

func checkRunning(dataDir string) Check {
	st, err := ReadRunState(dataDir)
	if err != nil {
		return check("실행 중인 Agent", CheckWarn, "이 데이터 디렉토리로 실행 중인 Agent가 없습니다")
	}
	if !st.Alive() {
		return check("실행 중인 Agent", CheckWarn,
			"pid %d 의 상태 파일이 남아 있지만 프로세스는 종료되었습니다", st.PID)
	}
	detail := fmt.Sprintf("pid %d, 버전 %s", st.PID, st.Version)
	if st.CurrentJobID != "" {
		detail += fmt.Sprintf(", job %s 실행 중", st.CurrentJobID)
	}
	return check("실행 중인 Agent", CheckOK, "%s", detail)
}
