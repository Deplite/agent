package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/credstore"
)

// credentialsExist reports whether the data dir already holds an
// identity, so start can tell a first run from a restart.
func credentialsExist(dir string) bool { return credstore.New(dir).Exists() }

func runStart(args []string) int {
	fs := newFlagSet("start",
		"deplite-agent start [--data-dir DIR] [--workflows-dir DIR] [--heartbeat 30s] [--deploy-sync=false]",
		"Agent를 실행해 대시보드가 보내는 작업을 처리합니다.")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	hb := fs.Duration("heartbeat", 30*time.Second, "하트비트 주기")
	deploySync := fs.Bool("deploy-sync", true, "앱 배포 상태 동기화를 함께 수행합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, wfDir, err := dirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}

	if !credentialsExist(dir) {
		return errorf("%s 에 자격증명이 없습니다.\n  deplite-agent install --code <1회용_설치_코드> 로 먼저 등록해주세요.", dir)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err = agent.Start(ctx, agent.StartOptions{
		DataDir:           dir,
		WorkflowsDir:      wfDir,
		Version:           version,
		HeartbeatInterval: *hb,
		DisableDeploySync: !*deploySync,
	})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, agent.ErrAgentRevoked):
		return errorf("서버가 이 Agent의 자격증명을 거부했습니다. 대시보드에서 다시 설치해주세요")
	default:
		return errorf("실행에 실패했습니다: %v", err)
	}
}
