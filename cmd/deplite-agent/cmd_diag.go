package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/credstore"
	"github.com/Deplite/agent/internal/limiter"
	"github.com/Deplite/agent/internal/systemd"
	"github.com/Deplite/agent/internal/textutil"
	"github.com/Deplite/agent/internal/workflow"
)

func runStatus(args []string) int {
	fs := newFlagSet("status",
		"deplite-agent status [--data-dir DIR] [--workflows-dir DIR] [--json]",
		"등록 정보와 실행 상태를 보여줍니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	asJSON := fs.Bool("json", false, "JSON으로 출력합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, wfDir, err := dirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}
	serviceInfo, err := systemd.Inspect(context.Background(), runtime.GOOS, systemd.UnitPath, systemd.OSOps{})
	if err != nil {
		return errorf("서비스 설정을 읽지 못했습니다: %v", err)
	}
	store := credstore.New(dir)
	report := map[string]any{
		"dataDir":      dir,
		"workflowsDir": wfDir,
		"logDir":       agent.ResolveLogDir(dir),
		"installed":    store.Exists(),
	}
	var id credstore.Identity
	if store.Exists() {
		loaded, _, err := store.Load()
		if err != nil {
			return errorf("자격증명을 읽지 못했습니다: %v", err)
		}
		id = loaded
		report["agentId"] = id.AgentID
		report["organizationId"] = id.OrganizationID
		report["baseUrl"] = id.BaseURL
	}
	wfs, bad := workflow.Scan(wfDir)
	report["workflows"] = len(wfs)
	report["workflowErrors"] = len(bad)
	runState, runErr := agent.ReadRunState(dir)
	running := runErr == nil && runState.Alive()
	report["running"] = running
	if running {
		report["state"] = runState
	}
	if serviceInfo != nil {
		report["service"] = map[string]any{
			"unitPath": serviceInfo.UnitPath, "user": serviceInfo.User,
			"execStart": serviceInfo.ExecStart, "dataDir": serviceInfo.DataDir,
			"workflowsDir": serviceInfo.WorkflowsDir, "active": serviceInfo.Active,
			"activeState": serviceInfo.ActiveState,
		}
		if hint := systemd.DataDirHint(serviceInfo, dir); hint != "" {
			report["serviceDataDirHint"] = hint
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return errorf("%v", err)
		}
		return 0
	}

	var t textutil.Table
	if !store.Exists() {
		t.Add("등록", "아직 등록되지 않았습니다")
	} else {
		t.Add("agentId", id.AgentID)
		t.Add("organizationId", id.OrganizationID)
		t.Add("백엔드", id.BaseURL)
	}
	t.Add("데이터 디렉토리", dir)
	t.Add("워크플로우 디렉토리", fmt.Sprintf("%s (%d개%s)", wfDir, len(wfs), errNote(len(bad))))
	t.Add("로그 디렉토리", agent.ResolveLogDir(dir))
	if serviceInfo != nil {
		t.Add("서비스", fmt.Sprintf("%s (User=%s, 상태=%s, 데이터 디렉토리=%s)",
			serviceInfo.UnitPath, serviceInfo.User, serviceInfo.ActiveState, serviceInfo.DataDir))
		if hint := systemd.DataDirHint(serviceInfo, dir); hint != "" {
			t.Add("서비스 데이터 안내", hint)
		}
	}
	switch {
	case running:
		t.Add("실행 상태", fmt.Sprintf("실행 중 (pid %d, 버전 %s, %s 시작)",
			runState.PID, runState.Version, runState.StartedAt.Local().Format(time.RFC3339)))
		t.Add("스트림", streamNote(runState))
		t.Add("마지막 하트비트", heartbeatNote(runState))
		if runState.CurrentJobID != "" {
			t.Add("실행 중인 작업", fmt.Sprintf("%s (%s)", runState.CurrentJobID, runState.CurrentWorkflow))
		}
	case runErr == nil:
		t.Add("실행 상태", fmt.Sprintf("종료됨 (pid %d 의 상태 파일이 남아 있습니다)", runState.PID))
	default:
		t.Add("실행 상태", "실행 중이 아닙니다")
	}
	t.Render(os.Stdout)
	return 0
}

func runDoctor(args []string) int {
	fs := newFlagSet("doctor",
		"deplite-agent doctor [--data-dir DIR] [--workflows-dir DIR]",
		"설치·연결·권한을 한 번에 점검합니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	timeout := fs.Duration("timeout", 10*time.Second, "백엔드 연결 점검 제한 시간")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, wfDir, err := dirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	checks := agent.Doctor(ctx, agent.DoctorOptions{
		DataDir:      dir,
		WorkflowsDir: wfDir,
		Timeout:      *timeout,
	})

	var t textutil.Table
	failed := 0
	for _, c := range checks {
		if c.Result == agent.CheckFail {
			failed++
		}
		t.Add(string(c.Result), c.Name, c.Detail)
	}
	t.Render(os.Stdout)
	if failed > 0 {
		fmt.Printf("\n%d개 항목이 실패했습니다.\n", failed)
		return 1
	}
	fmt.Println("\n모든 점검을 통과했습니다.")
	return 0
}

func runLogs(args []string) int {
	fs := newFlagSet("logs",
		"deplite-agent logs [--job ID] [--stream system|raw] [--follow] [--list]",
		"지난 작업의 로그를 봅니다. 기본은 가장 최근 작업입니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	job := fs.String("job", "", "작업 ID (기본값: 가장 최근 작업)")
	stream := fs.String("stream", "", "system 또는 raw 하나만 봅니다")
	follow := fs.Bool("follow", false, "새 줄이 쌓이는 대로 계속 출력합니다")
	list := fs.Bool("list", false, "남아 있는 작업 로그 목록을 보여줍니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stream != "" && *stream != "system" && *stream != "raw" {
		return errorf("--stream 은 system 또는 raw 여야 합니다")
	}
	dir, err := resolveDataDir(*dataDir)
	if err != nil {
		return errorf("%v", err)
	}
	logDir := agent.ResolveLogDir(dir)

	jobs, err := jobDirs(logDir)
	if err != nil {
		return errorf("로그 디렉토리를 열 수 없습니다: %v", err)
	}
	if len(jobs) == 0 {
		fmt.Printf("%s 에 남아 있는 작업 로그가 없습니다.\n", logDir)
		return 0
	}

	if *list {
		var t textutil.Table
		t.Add("작업 ID", "마지막 기록")
		for _, j := range jobs {
			t.Add(j.id, j.modTime.Local().Format(time.RFC3339))
		}
		t.Render(os.Stdout)
		return 0
	}

	target := jobs[0].id
	if *job != "" {
		target = *job
		// A job id names one directory under the log dir; anything with a
		// separator in it would read somewhere else entirely.
		if target != filepath.Base(target) || target == "." || target == ".." {
			return errorf("작업 ID가 올바르지 않습니다: %s", target)
		}
		if _, err := os.Stat(filepath.Join(logDir, target)); err != nil {
			return errorf("작업 %s 의 로그가 없습니다", target)
		}
	}

	streams := []string{"system", "raw"}
	if *stream != "" {
		streams = []string{*stream}
	}
	fmt.Printf("# %s\n", filepath.Join(logDir, target))

	if !*follow {
		printed := false
		for _, s := range streams {
			path := filepath.Join(logDir, target, s+".log")
			b, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return errorf("%v", err)
			}
			if len(streams) > 1 {
				fmt.Printf("\n--- %s ---\n", s)
			}
			os.Stdout.Write(b)
			printed = true
		}
		if !printed {
			fmt.Println("(내용 없음)")
		}
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return followLogs(ctx, logDir, target, streams)
}

func runLimits(args []string) int {
	fs := newFlagSet("limits",
		"deplite-agent limits [--workflows-dir DIR] [--reset NAME] [--reset-all]",
		"워크플로우 실행 제한(cooldown, bucket) 상태를 보거나 초기화합니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	reset := fs.String("reset", "", "이 워크플로우의 제한 상태를 초기화합니다")
	resetAll := fs.Bool("reset-all", false, "모든 워크플로우의 제한 상태를 초기화합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, wfDir, err := dirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}
	wfs, _ := workflow.Scan(wfDir)
	manager := limiter.New(filepath.Join(dir, "limits"))

	if *reset != "" || *resetAll {
		targets := make([]string, 0, len(wfs))
		for _, wf := range wfs {
			if *resetAll || wf.Name == *reset {
				targets = append(targets, wf.Name)
			}
		}
		if len(targets) == 0 {
			return errorf("워크플로우 %q 를 찾을 수 없습니다", *reset)
		}
		for _, name := range targets {
			if err := manager.Reset(name); err != nil {
				return errorf("%v", err)
			}
			fmt.Printf("%s 의 제한 상태를 초기화했습니다.\n", name)
		}
		return 0
	}

	var t textutil.Table
	t.Add("워크플로우", "제한", "상태", "비고")
	rows := 0
	for _, wf := range wfs {
		statuses, err := manager.Inspect(&wf, time.Now())
		if err != nil {
			return errorf("%v", err)
		}
		for _, st := range statuses {
			rows++
			state, note := "실행 가능", "-"
			if !st.Allowed {
				state = fmt.Sprintf("대기 %s", st.RetryAfter.Round(time.Second))
			}
			switch st.Type {
			case "bucket":
				note = fmt.Sprintf("토큰 %.1f/%d", st.Tokens, st.Capacity)
			case "cooldown":
				if !st.LastFinish.IsZero() {
					note = fmt.Sprintf("마지막 종료 %s (%s)",
						st.LastFinish.Local().Format(time.RFC3339), dash(st.LastStatus))
				}
			}
			t.Add(wf.Name, st.Type, state, note)
		}
	}
	t.Render(os.Stdout)
	if rows == 0 {
		fmt.Println("limits 를 선언한 워크플로우가 없습니다.")
	}
	return 0
}

type jobDir struct {
	id      string
	modTime time.Time
}

// jobDirs lists job log directories, newest first.
func jobDirs(logDir string) ([]jobDir, error) {
	entries, err := os.ReadDir(logDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]jobDir, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, jobDir{id: e.Name(), modTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].modTime.After(out[j].modTime) })
	return out, nil
}

// followLogs prints what each stream already holds and then keeps
// printing new bytes until the context is canceled.
func followLogs(ctx context.Context, logDir, jobID string, streams []string) int {
	offsets := make(map[string]int64, len(streams))
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, s := range streams {
			path := filepath.Join(logDir, jobID, s+".log")
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := f.Seek(offsets[s], io.SeekStart); err != nil {
				_ = f.Close()
				continue
			}
			n, _ := io.Copy(os.Stdout, f)
			offsets[s] += n
			_ = f.Close()
		}
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
		}
	}
}

func errNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", 오류 %d개", n)
}

func streamNote(s agent.RunState) string {
	if !s.StreamConnected {
		return "연결되지 않았습니다"
	}
	return fmt.Sprintf("연결됨 (%s)", s.StreamConnectedAt.Local().Format(time.RFC3339))
}

func heartbeatNote(s agent.RunState) string {
	if s.LastHeartbeatAt.IsZero() {
		return "아직 없습니다"
	}
	at := s.LastHeartbeatAt.Local().Format(time.RFC3339)
	if s.LastHeartbeatError != "" {
		return fmt.Sprintf("%s 실패: %s", at, s.LastHeartbeatError)
	}
	return at
}
