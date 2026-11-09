package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/systemd"
	"github.com/Deplite/agent/internal/update"
)

func TestVerifyUpdateBinaryHonorsTimeout(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("update supports Linux and macOS executables")
	}
	path := filepath.Join(t.TempDir(), "slow-version")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err := verifyUpdateBinaryWithTimeout(path, "1.0.0", 50*time.Millisecond)
	if err == nil {
		t.Fatal("slow version command unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("version timeout took %s, want under 2s", elapsed)
	}
}

func TestUpdateCheckAndAlreadyCurrent(t *testing.T) {
	var out, errOut bytes.Buffer
	latestCalls := 0
	deps := updateCmdDeps{
		Out: &out, Err: &errOut, CurrentVersion: "1.2.0",
		Latest: func(context.Context, update.Options) (update.Version, error) {
			latestCalls++
			return testVersion(t, "v1.3.0"), nil
		},
		Executable: func() (string, error) { t.Fatal("check must not inspect executable"); return "", nil },
	}
	if code := runUpdateWithDeps([]string{"--check"}, deps); code != 0 {
		t.Fatalf("check exit = %d, stderr %q", code, errOut.String())
	}
	if got, want := out.String(), "새 버전이 있습니다: 1.2.0 → 1.3.0\nsudo deplite-agent update 로 업데이트할 수 있습니다\n"; got != want {
		t.Fatalf("check output = %q, want %q", got, want)
	}
	out.Reset()
	if code := runUpdateWithDeps([]string{"--check"}, updateCmdDeps{
		Out: &out, CurrentVersion: "1.3.0",
		Latest: func(context.Context, update.Options) (update.Version, error) { return testVersion(t, "v1.3.0"), nil },
	}); code != 0 || out.String() != "최신 버전입니다 (1.3.0)\n" {
		t.Fatalf("current check = %d, %q", code, out.String())
	}
	out.Reset()
	for _, version := range []string{"v1.3.0", "1.3.0"} {
		out.Reset()
		if code := runUpdateWithDeps([]string{"--version", version}, updateCmdDeps{
			Out: &out, CurrentVersion: "1.3.0",
		}); code != 0 || out.String() != "이미 1.3.0입니다\n" {
			t.Errorf("already current (%s) = %d, %q", version, code, out.String())
		}
	}
	if latestCalls != 1 {
		t.Fatalf("latest calls = %d", latestCalls)
	}
}

func TestUpdateDowngradeConfirmationAndYes(t *testing.T) {
	var out, errOut bytes.Buffer
	asked := false
	question := ""
	deps := baseUpdateDeps(t, &out, &errOut)
	deps.CurrentVersion = "1.2.0"
	deps.IsTerminal = func() bool { return true }
	deps.Ask = func(value string) bool { asked = true; question = value; return false }
	if code := runUpdateWithDeps([]string{"--version", "v1.1.0"}, deps); code != 1 || !asked || question != "현재 버전(1.2.0)보다 낮은 버전(1.1.0)으로 다운그레이드할까요?" || !strings.Contains(out.String(), "취소했습니다") {
		t.Fatalf("declined downgrade = %d, asked=%v, out=%q, err=%q", code, asked, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	asked = false
	deps = baseUpdateDeps(t, &out, &errOut)
	deps.CurrentVersion = "1.2.0"
	deps.IsTerminal = func() bool { return false }
	deps.Ask = func(string) bool { asked = true; return true }
	if code := runUpdateWithDeps([]string{"--version", "v1.1.0"}, deps); code != 1 || asked || !strings.Contains(errOut.String(), "--yes") {
		t.Fatalf("nonterminal downgrade = %d, asked=%v, err=%q", code, asked, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	deps = baseUpdateDeps(t, &out, &errOut)
	deps.CurrentVersion = "1.2.0"
	deps.IsTerminal = func() bool { return false }
	deps.Ask = func(string) bool { t.Fatal("--yes must bypass prompt"); return false }
	deps.Download = func(context.Context, update.Version, string, string, string, update.Options) (string, error) {
		return "", errors.New("test stop")
	}
	if code := runUpdateWithDeps([]string{"--version", "v1.1.0", "--yes"}, deps); code != 1 || !strings.Contains(out.String(), "1.2.0 → 1.1.0") || !strings.Contains(errOut.String(), "test stop") {
		t.Fatalf("--yes downgrade = %d, out=%q, err=%q", code, out.String(), errOut.String())
	}
}

func TestUpdateDevVersionAndPreflightGuards(t *testing.T) {
	t.Run("dev version", func(t *testing.T) {
		var out, errOut bytes.Buffer
		deps := baseUpdateDeps(t, &out, &errOut)
		deps.CurrentVersion = "dev"
		deps.Download = func(context.Context, update.Version, string, string, string, update.Options) (string, error) {
			return "", errors.New("checksum test failure")
		}
		if code := runUpdateWithDeps([]string{"--version", "v1.0.0"}, deps); code != 1 || !strings.Contains(out.String(), "현재 버전을 알 수 없어(dev) 릴리스 버전(1.0.0)으로 바꿉니다") || !strings.Contains(errOut.String(), "checksum test failure") {
			t.Fatalf("dev update = %d, out=%q, err=%q", code, out.String(), errOut.String())
		}
		target, _ := deps.Executable()
		contents, err := os.ReadFile(target)
		if err != nil || string(contents) != "old executable" {
			t.Fatalf("target changed after download failure: %q, %v", contents, err)
		}
	})

	t.Run("checksum download failure leaves target alone", func(t *testing.T) {
		var out, errOut bytes.Buffer
		deps := baseUpdateDeps(t, &out, &errOut)
		deps.CurrentVersion = "1.0.0"
		target, _ := deps.Executable()
		archive := updateTestArchive(t, []byte("replacement"))
		deps.ReleaseBaseURL = "https://releases.test"
		deps.HTTPClient = &http.Client{Transport: updateTestRoundTripper(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/checksums.txt") {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(archive)
		})}
		deps.Download = update.Download
		if code := runUpdateWithDeps([]string{"--version", "v1.1.0", "--skip-signature"}, deps); code != 1 || !strings.Contains(errOut.String(), "checksums.txt") {
			t.Fatalf("checksum failure = %d, err=%q", code, errOut.String())
		}
		contents, err := os.ReadFile(target)
		if err != nil || string(contents) != "old executable" {
			t.Fatalf("target changed after checksum failure: %q, %v", contents, err)
		}
	})

	t.Run("container", func(t *testing.T) {
		var errOut bytes.Buffer
		deps := baseUpdateDeps(t, &bytes.Buffer{}, &errOut)
		deps.MarkerExists = func(string) bool { return true }
		if code := runUpdateWithDeps([]string{"--version", "v2.0.0"}, deps); code != 1 || !strings.Contains(errOut.String(), "컨테이너 안에서는 업데이트할 수 없습니다") {
			t.Fatalf("container guard = %d, %q", code, errOut.String())
		}
	})

	t.Run("service executable mismatch", func(t *testing.T) {
		var errOut bytes.Buffer
		deps := baseUpdateDeps(t, &bytes.Buffer{}, &errOut)
		deps.InspectService = func(context.Context) (*systemd.Info, error) {
			return &systemd.Info{ExecStart: "/opt/other-agent start", Active: true}, nil
		}
		if code := runUpdateWithDeps([]string{"--version", "v2.0.0"}, deps); code != 1 || !strings.Contains(errOut.String(), "서비스 실행 파일: /opt/other-agent") || !strings.Contains(errOut.String(), "sudo /opt/other-agent update") {
			t.Fatalf("service guard = %d, %q", code, errOut.String())
		}
	})

	t.Run("not writable", func(t *testing.T) {
		var errOut bytes.Buffer
		deps := baseUpdateDeps(t, &bytes.Buffer{}, &errOut)
		deps.CanWriteDir = func(string) bool { return false }
		if code := runUpdateWithDeps([]string{"--version", "v2.0.0"}, deps); code != 1 || !strings.Contains(errOut.String(), "권한이 없습니다. sudo deplite-agent update로 실행해주세요") {
			t.Fatalf("permission guard = %d, %q", code, errOut.String())
		}
	})

	t.Run("self check failure", func(t *testing.T) {
		var out, errOut bytes.Buffer
		deps := baseUpdateDeps(t, &out, &errOut)
		replaced := false
		deps.VerifyBinary = func(string, string) error { return errors.New("unexpected version output") }
		deps.ReplaceBinary = func(string, string) error { replaced = true; return nil }
		if code := runUpdateWithDeps([]string{"--version", "v2.0.0"}, deps); code != 1 || replaced || !strings.Contains(errOut.String(), "새 실행 파일 자체 점검에 실패했습니다") {
			t.Fatalf("self check = %d, replaced=%v, err=%q", code, replaced, errOut.String())
		}
		target, _ := deps.Executable()
		contents, err := os.ReadFile(target)
		if err != nil || string(contents) != "old executable" {
			t.Fatalf("target changed after self-check failure: %q, %v", contents, err)
		}
	})
}

func TestWaitForJobUsesInjectedClock(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(1000, 0)
	reads := 0
	deps := completeUpdateCmdDeps(updateCmdDeps{
		Out:   &out,
		Now:   func() time.Time { return now },
		Sleep: func(duration time.Duration) { now = now.Add(duration) },
		ReadRunState: func(string) (agent.RunState, error) {
			reads++
			if reads == 1 {
				return agent.RunState{PID: 10, CurrentWorkflow: "deploy", CurrentJobID: "job-1"}, nil
			}
			return agent.RunState{PID: 10}, nil
		},
		Alive: func(agent.RunState) bool { return true },
	})
	if err := waitForJob(deps, "/data"); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || !strings.Contains(out.String(), "실행 중인 job의 종료를 기다립니다 (workflow: deploy, job ID: job-1)") {
		t.Fatalf("reads=%d output=%q", reads, out.String())
	}

	reads = 0
	out.Reset()
	now = time.Unix(2000, 0)
	deps.ReadRunState = func(string) (agent.RunState, error) {
		reads++
		return agent.RunState{PID: 10, CurrentWorkflow: "deploy", CurrentJobID: "job-2"}, nil
	}
	if err := waitForJob(deps, "/data"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("timeout error = %v", err)
	}
	if now.Sub(time.Unix(2000, 0)) != 10*time.Minute {
		t.Fatalf("fake time advanced %s, want 10m", now.Sub(time.Unix(2000, 0)))
	}
}

func TestWaitForRestartTimeoutUsesInjectedClock(t *testing.T) {
	now := time.Unix(3000, 0)
	deps := completeUpdateCmdDeps(updateCmdDeps{
		Now:   func() time.Time { return now },
		Sleep: func(duration time.Duration) { now = now.Add(duration) },
		ReadRunState: func(string) (agent.RunState, error) {
			return agent.RunState{PID: 41, Version: "1.0.0"}, nil
		},
		Alive: func(agent.RunState) bool { return true },
	})
	if err := waitForRestart(deps, "/data", 41, "1.1.0"); err == nil || !strings.Contains(err.Error(), "60초") {
		t.Fatalf("restart timeout error = %v", err)
	}
	if now.Sub(time.Unix(3000, 0)) != 60*time.Second {
		t.Fatalf("fake time advanced %s, want 60s", now.Sub(time.Unix(3000, 0)))
	}
}

func TestUpdateActiveServiceRestartAndForce(t *testing.T) {
	for _, test := range []struct {
		name       string
		force      bool
		userID     int
		restartErr error
		wantCode   int
		wantOutput string
		wantError  string
	}{
		{name: "active job drains then restarts", wantOutput: "deplite-agent를 새 버전(1.1.0)으로 다시 시작했습니다"},
		{name: "force skips job wait", force: true, wantOutput: "deplite-agent를 새 버전(1.1.0)으로 다시 시작했습니다"},
		{name: "non-root restarts through sudo", force: true, userID: 1000, wantOutput: "deplite-agent를 새 버전(1.1.0)으로 다시 시작했습니다"},
		{name: "restart failure reports rollback", force: true, restartErr: errors.New("restart failed"), wantCode: 1, wantError: "sudo mv"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			deps := baseUpdateDeps(t, &out, &errOut)
			deps.CurrentVersion = "1.0.0"
			target, _ := deps.Executable()
			deps.InspectService = func(context.Context) (*systemd.Info, error) {
				return &systemd.Info{ExecStart: target + " start", DataDir: "/data", Active: true}, nil
			}
			var sysOps fakeUpdateSystemdOps
			sysOps.restartErr = test.restartErr
			deps.SystemdOps = &sysOps
			deps.EffectiveUserID = func() int { return test.userID }
			deps.Now = func() time.Time { return time.Unix(100, 0) }
			sleeps := 0
			deps.Sleep = func(time.Duration) { sleeps++ }
			reads := 0
			deps.Alive = func(agent.RunState) bool { return true }
			deps.ReadRunState = func(string) (agent.RunState, error) {
				reads++
				if reads == 1 || (!test.force && reads == 2) {
					return agent.RunState{PID: 41, Version: "1.0.0", CurrentWorkflow: "deploy", CurrentJobID: "job-42"}, nil
				}
				if !test.force && reads == 3 {
					return agent.RunState{PID: 41, Version: "1.0.0"}, nil
				}
				return agent.RunState{PID: 42, Version: "1.1.0"}, nil
			}
			if test.restartErr != nil {
				sysOps.restartErr = test.restartErr
			}
			args := []string{"--version", "v1.1.0"}
			if test.force {
				args = append(args, "--force")
			}
			if code := runUpdateWithDeps(args, deps); code != test.wantCode {
				t.Fatalf("exit = %d, want %d; out=%q err=%q", code, test.wantCode, out.String(), errOut.String())
			}
			if test.force && sleeps != 0 {
				t.Fatalf("--force waited %d times", sleeps)
			}
			if test.wantOutput != "" && !strings.Contains(out.String(), test.wantOutput) {
				t.Fatalf("output %q does not include %q", out.String(), test.wantOutput)
			}
			if test.wantError != "" && (!strings.Contains(errOut.String(), test.wantError) || !strings.Contains(errOut.String(), "journalctl")) {
				t.Fatalf("error output %q", errOut.String())
			}
			if len(sysOps.commands) == 0 || !strings.Contains(strings.Join(sysOps.commands[0], " "), "restart deplite-agent") {
				t.Fatalf("systemctl commands = %#v", sysOps.commands)
			}
			if test.userID != 0 && sysOps.commands[0][0] != "/test/sudo" {
				t.Fatalf("non-root restart did not use sudo: %#v", sysOps.commands[0])
			}
		})
	}
}

func TestUpdateWithoutServicePrintsForegroundHint(t *testing.T) {
	var out bytes.Buffer
	deps := baseUpdateDeps(t, &out, &bytes.Buffer{})
	deps.CurrentVersion = "1.0.0"
	deps.ReadRunState = func(string) (agent.RunState, error) { return agent.RunState{PID: 20}, nil }
	deps.Alive = func(agent.RunState) bool { return true }
	if code := runUpdateWithDeps([]string{"--version", "v1.1.0"}, deps); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "다음 시작부터 새 버전(1.1.0)이 적용됩니다") || !strings.Contains(out.String(), "실행 중인 agent를 다시 시작해주세요") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRestartFailureLeavesTargetAndBackupForManualRollback(t *testing.T) {
	var out, errOut bytes.Buffer
	deps := baseUpdateDeps(t, &out, &errOut)
	target, _ := deps.Executable()
	deps.InspectService = func(context.Context) (*systemd.Info, error) {
		return &systemd.Info{ExecStart: target + " start", DataDir: "/data", Active: true}, nil
	}
	deps.StageBinary = update.StageBinary
	deps.ReplaceBinary = update.Replace
	deps.ReadRunState = func(string) (agent.RunState, error) { return agent.RunState{PID: 50}, nil }
	deps.Alive = func(agent.RunState) bool { return false }
	var sysOps fakeUpdateSystemdOps
	sysOps.restartErr = errors.New("restart failed")
	deps.SystemdOps = &sysOps
	if code := runUpdateWithDeps([]string{"--version", "v1.1.0", "--force"}, deps); code != 1 {
		t.Fatalf("exit = %d, out=%q, err=%q", code, out.String(), errOut.String())
	}
	for path, want := range map[string]string{target: "new executable", target + ".prev": "old executable"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", path, got, err)
		}
	}
	if strings.Contains(errOut.String(), "되돌렸습니다") || !strings.Contains(errOut.String(), "sudo mv") {
		t.Fatalf("restart failure guidance = %q", errOut.String())
	}
}

func baseUpdateDeps(t *testing.T, out, errOut io.Writer) updateCmdDeps {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "deplite-agent")
	if err := os.WriteFile(target, []byte("old executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "release.tar.gz")
	if err := os.WriteFile(archivePath, updateTestArchive(t, []byte("new executable")), 0o600); err != nil {
		t.Fatal(err)
	}
	return updateCmdDeps{
		Out: out, Err: errOut, CurrentVersion: "1.0.0", GOOS: "linux", GOARCH: "amd64",
		Executable:   func() (string, error) { return target, nil },
		EvalSymlinks: func(path string) (string, error) { return filepath.Clean(path), nil },
		CanWriteDir:  func(string) bool { return true },
		MarkerPath:   "/test/.dockerenv", MarkerExists: func(string) bool { return false },
		IsTerminal: func() bool { return false }, Ask: func(string) bool { return false },
		InspectService: func(context.Context) (*systemd.Info, error) { return nil, nil },
		ReadRunState:   func(string) (agent.RunState, error) { return agent.RunState{}, os.ErrNotExist },
		Alive:          func(agent.RunState) bool { return false },
		DataDirs:       func() (string, error) { return dir, nil },
		Latest:         func(context.Context, update.Options) (update.Version, error) { return testVersion(t, "v1.1.0"), nil },
		Download: func(context.Context, update.Version, string, string, string, update.Options) (string, error) {
			return archivePath, nil
		},
		StageBinary:   func(string, string) (string, func(), error) { return filepath.Join(dir, "staged"), func() {}, nil },
		VerifyBinary:  func(string, string) error { return nil },
		ReplaceBinary: func(string, string) error { return nil },
		Now:           func() time.Time { return time.Unix(100, 0) }, Sleep: func(time.Duration) {},
		EffectiveUserID: func() int { return 0 },
	}
}

func testVersion(t *testing.T, tag string) update.Version {
	t.Helper()
	version, err := update.ParseTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func updateTestArchive(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	header := make([]byte, 512)
	copy(header[0:100], "deplite-agent")
	copy(header[100:108], "0000755\x00")
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", len(body)))
	copy(header[136:148], "00000000000\x00")
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	header[156] = '0'
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	var checksum int64
	for _, value := range header {
		checksum += int64(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	if _, err := gz.Write(header); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(body); err != nil {
		t.Fatal(err)
	}
	padding := (512 - len(body)%512) % 512
	if padding > 0 {
		_, _ = gz.Write(make([]byte, padding))
	}
	_, _ = gz.Write(make([]byte, 1024))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type updateTestRoundTripper func(http.ResponseWriter, *http.Request)

func (roundTrip updateTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	roundTrip(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func flagIf(yes bool, value string) string {
	if yes {
		return value
	}
	return ""
}

type fakeUpdateSystemdOps struct {
	restartErr error
	commands   [][]string
}

func (f *fakeUpdateSystemdOps) IsDir(string) bool { return false }
func (f *fakeUpdateSystemdOps) LookPath(name string) (string, error) {
	if name == "systemctl" {
		return "/test/systemctl", nil
	}
	if name == "sudo" {
		return "/test/sudo", nil
	}
	return "", errors.New("not found")
}
func (f *fakeUpdateSystemdOps) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (f *fakeUpdateSystemdOps) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, append([]string{name}, args...))
	return []byte("systemctl output"), f.restartErr
}
func (f *fakeUpdateSystemdOps) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *fakeUpdateSystemdOps) CreateTemp([]byte) (string, func(), error) {
	return "", func() {}, nil
}
func (f *fakeUpdateSystemdOps) MkdirAll(string, os.FileMode) error { return nil }
func (f *fakeUpdateSystemdOps) Chown(string, int, int) error       { return nil }
func (f *fakeUpdateSystemdOps) Remove(string) error                { return nil }

var _ systemd.Ops = (*fakeUpdateSystemdOps)(nil)
