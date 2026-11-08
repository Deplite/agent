package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Deplite/agent/internal/systemd"
)

func testWorkflowDeps(t *testing.T, out, stderr *bytes.Buffer) workflowCmdDeps {
	t.Helper()
	for _, key := range []string{"DEPLITE_DATA_DIR", "DEPLITE_WORKFLOWS_DIR", "DEPLITE_BASE_URL", "DEPLITE_INSTALL_CODE", "DEPLITE_TOKEN", "DEPLITE_ENROLLMENT_TOKEN", "DEPLITE_LOG_DIR", "VISUAL", "EDITOR"} {
		t.Setenv(key, "")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	deps := defaultWorkflowCmdDeps()
	deps.Out, deps.Err = out, stderr
	deps.IsTerminal = func() bool { return true }
	deps.LookPath = func(name string) (string, error) { return "/fake/" + name, nil }
	deps.ReadServiceUnit = func() (*systemd.Info, error) { return nil, nil }
	deps.Ask = func(string, bool) bool { return false }
	deps.Confirm = func(string) bool { return false }
	return deps
}

func validManageWorkflow(name string) []byte {
	return []byte("name: " + name + "\ndescription: \"\"\nsteps:\n  - name: hello\n    run: echo hello\n")
}

func writeManageWorkflow(t *testing.T, path, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, validManageWorkflow(name), 0o640); err != nil {
		t.Fatal(err)
	}
}

func fakeEditor(t *testing.T, edit func(int, string, []byte) []byte) (func(string, ...string) error, *int) {
	t.Helper()
	calls := 0
	run := func(_ string, args ...string) error {
		calls++
		path := args[len(args)-1]
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		updated := edit(calls, path, body)
		if updated != nil {
			return os.WriteFile(path, updated, 0o600)
		}
		return nil
	}
	return run, &calls
}

func TestAddWorkflow(t *testing.T) {
	t.Run("success and permissions", func(t *testing.T) {
		dir := t.TempDir()
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, body []byte) []byte {
			return bytes.Replace(body, []byte(`description: ""`), []byte(`description: "updated"`), 1)
		})
		code := runAddWithDeps([]string{"hello", "--workflows-dir", dir, "--editor", "fake --wait"}, deps)
		if code != 0 {
			t.Fatalf("runAdd = %d, stderr=%s", code, stderr.String())
		}
		path := filepath.Join(dir, "hello.yml")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`description: "updated"`)) {
			t.Fatalf("saved content = %s", body)
		}
		mode := fileMode(t, path)
		if mode&0o600 != 0o600 || mode&0o022 != 0 {
			t.Fatalf("file mode = %04o", mode)
		}
		if !strings.Contains(out.String(), "저장했습니다: "+path) || !strings.Contains(out.String(), "재시작 없이") {
			t.Fatalf("output = %s", out.String())
		}
	})

	t.Run("invalid, existing, unchanged and nonterminal", func(t *testing.T) {
		dir := t.TempDir()
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, body []byte) []byte { return body })
		if code := runAddWithDeps([]string{"bad/name", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "워크플로우 이름은") {
			t.Fatalf("invalid name: code=%d stderr=%s", code, stderr.String())
		}
		stderr.Reset()
		if err := os.WriteFile(filepath.Join(dir, "taken.yaml"), []byte("broken"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runAddWithDeps([]string{"taken", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "파일이 이미 있습니다") {
			t.Fatalf("existing file: code=%d stderr=%s", code, stderr.String())
		}
		stderr.Reset()
		stderr.Reset()
		if code := runAddWithDeps([]string{"plain", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "내용이 바뀌지 않아") {
			t.Fatalf("unchanged add: code=%d stderr=%s", code, stderr.String())
		}
		if strings.Contains(stderr.String(), "오류:") {
			t.Fatalf("unchanged add included error prefix: %s", stderr.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "plain.yml")); !os.IsNotExist(err) {
			t.Fatalf("unchanged add created file: %v", err)
		}
		deps.IsTerminal = func() bool { return false }
		stderr.Reset()
		if code := runAddWithDeps([]string{"nonterminal", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "터미널에서") {
			t.Fatalf("nonterminal add: code=%d stderr=%s", code, stderr.String())
		}
		stderr.Reset()
		if code := runAddWithDeps([]string{"missing-dir", "--workflows-dir", filepath.Join(dir, "absent")}, deps); code != 1 || !strings.Contains(stderr.String(), "워크플로우 디렉토리가 없습니다:") {
			t.Fatalf("missing directory: code=%d stderr=%s", code, stderr.String())
		}
	})

	t.Run("name must match argument", func(t *testing.T) {
		dir := t.TempDir()
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var mismatchBuffer string
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, _ []byte) []byte {
			mismatchBuffer = path
			return validManageWorkflow("other")
		})
		deps.Ask = func(string, bool) bool { return false }
		if code := runAddWithDeps([]string{"hello", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), `name 을 "hello" 으로 두어야 합니다 (지금은 "other")`) {
			t.Fatalf("name mismatch: code=%d stderr=%s", code, stderr.String())
		}
		_ = os.Remove(mismatchBuffer)
	})

	t.Run("repair and decline", func(t *testing.T) {
		dir := t.TempDir()
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var buffer string
		deps.RunEditor, _ = fakeEditor(t, func(call int, path string, body []byte) []byte {
			buffer = path
			if call == 1 {
				return []byte("name: hello\nsteps: []\n")
			}
			return validManageWorkflow("hello")
		})
		asks := 0
		deps.Ask = func(question string, defaultYes bool) bool {
			if question != "다시 편집할까요?" || !defaultYes {
				t.Errorf("Ask(%q, %v)", question, defaultYes)
			}
			asks++
			return true
		}
		if code := runAddWithDeps([]string{"--workflows-dir", dir, "hello"}, deps); code != 0 || asks != 1 {
			t.Fatalf("repaired add: code=%d asks=%d stderr=%s", code, asks, stderr.String())
		}
		if _, err := os.Stat(buffer); !os.IsNotExist(err) {
			t.Fatalf("successful buffer remains: %v", err)
		}

		dir2 := t.TempDir()
		out.Reset()
		stderr.Reset()
		deps = testWorkflowDeps(t, &out, &stderr)
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, _ []byte) []byte {
			buffer = path
			return []byte("name: invalid\nsteps: []\n")
		})
		deps.Ask = func(string, bool) bool { return false }
		if code := runAddWithDeps([]string{"hello", "--workflows-dir", dir2}, deps); code != 1 {
			t.Fatalf("declined add code = %d", code)
		}
		if _, err := os.Stat(buffer); err != nil {
			t.Fatalf("declined buffer missing: %v", err)
		}
		if !strings.Contains(stderr.String(), buffer) || !strings.Contains(stderr.String(), "검사에 실패했습니다") {
			t.Fatalf("declined output = %s", stderr.String())
		}
		_ = os.Remove(buffer)
	})

	t.Run("blank buffer is discarded", func(t *testing.T) {
		dir := t.TempDir()
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var buffer string
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, _ []byte) []byte {
			buffer = path
			return []byte(" \n\t\n")
		})
		if code := runAddWithDeps([]string{"empty", "--workflows-dir", dir}, deps); code != 1 {
			t.Fatalf("blank add code = %d", code)
		}
		if stderr.String() != "내용이 비어 있어 저장하지 않았습니다.\n" {
			t.Fatalf("blank output = %q", stderr.String())
		}
		if _, err := os.Stat(buffer); !os.IsNotExist(err) {
			t.Fatalf("blank buffer remains: %v", err)
		}
	})

	t.Run("service directory mismatch", func(t *testing.T) {
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		deps.ReadServiceUnit = func() (*systemd.Info, error) {
			return &systemd.Info{WorkflowsDir: filepath.Join(t.TempDir(), "service")}, nil
		}
		calls := 0
		deps.RunEditor = func(string, ...string) error { calls++; return nil }
		if code := runAddWithDeps([]string{"hello"}, deps); code != 1 || calls != 0 || !strings.Contains(stderr.String(), "오류: 서비스는") || strings.Contains(stderr.String(), "오류: 참고:") || strings.Count(stderr.String(), "오류:") != 1 {
			t.Fatalf("service mismatch: code=%d calls=%d stderr=%s", code, calls, stderr.String())
		}
	})
}

func TestEditWorkflow(t *testing.T) {
	t.Run("unchanged and preserves mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "hello.yml")
		writeManageWorkflow(t, path, "hello")
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var buffer string
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, body []byte) []byte { buffer = path; return body })
		if code := runEditWithDeps([]string{"hello", "--workflows-dir", dir}, deps); code != 0 || !strings.Contains(out.String(), "변경 사항이 없습니다.") {
			t.Fatalf("unchanged edit: code=%d out=%s stderr=%s", code, out.String(), stderr.String())
		}
		if _, err := os.Stat(buffer); !os.IsNotExist(err) {
			t.Fatalf("unchanged buffer remains: %v", err)
		}

		out.Reset()
		deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, body []byte) []byte {
			return bytes.Replace(body, []byte(`description: ""`), []byte(`description: "edited"`), 1)
		})
		if code := runEditWithDeps([]string{"--workflows-dir", dir, "hello"}, deps); code != 0 {
			t.Fatalf("edit code=%d stderr=%s", code, stderr.String())
		}
		if mode := fileMode(t, path); mode != 0o640 {
			t.Fatalf("mode = %04o, want 0640", mode)
		}
	})

	t.Run("name and duplicate validation preserve buffer", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "hello.yml")
		writeManageWorkflow(t, path, "hello")
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var renameBuffer string
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, _ []byte) []byte {
			renameBuffer = path
			return validManageWorkflow("changed")
		})
		if code := runEditWithDeps([]string{"hello", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "이름은 바꿀 수 없습니다") {
			t.Fatalf("rename edit: code=%d stderr=%s", code, stderr.String())
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, validManageWorkflow("hello")) {
			t.Fatalf("source changed: %s", got)
		}
		_ = os.Remove(renameBuffer)

		dir2 := t.TempDir()
		broken := filepath.Join(dir2, "team", "broken.yml")
		if err := os.MkdirAll(filepath.Dir(broken), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(broken, []byte("broken: [\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeManageWorkflow(t, filepath.Join(dir2, "taken.yml"), "taken")
		stderr.Reset()
		deps = testWorkflowDeps(t, &out, &stderr)
		var duplicateBuffer string
		deps.RunEditor, _ = fakeEditor(t, func(_ int, path string, _ []byte) []byte {
			duplicateBuffer = path
			return validManageWorkflow("taken")
		})
		if code := runEditWithDeps([]string{"team/broken.yml", "--workflows-dir", dir2}, deps); code != 1 || !strings.Contains(stderr.String(), "같은 이름의 워크플로우가 이미 있습니다") {
			t.Fatalf("duplicate edit: code=%d stderr=%s", code, stderr.String())
		}
		_ = os.Remove(duplicateBuffer)
	})

	t.Run("external change and path restrictions", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "hello.yml")
		writeManageWorkflow(t, path, "hello")
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		var buffer string
		deps.RunEditor = func(_ string, args ...string) error {
			buffer = args[len(args)-1]
			edited := bytes.Replace(validManageWorkflow("hello"), []byte(`description: ""`), []byte(`description: "edited"`), 1)
			if err := os.WriteFile(args[len(args)-1], edited, 0o600); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("external change\n"), 0o600)
		}
		if code := runEditWithDeps([]string{"hello", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "편집하는 동안") {
			t.Fatalf("concurrent edit: code=%d stderr=%s", code, stderr.String())
		}
		_ = os.Remove(buffer)
		outside := filepath.Join(t.TempDir(), "outside.yml")
		writeManageWorkflow(t, outside, "outside")
		stderr.Reset()
		calls := 0
		deps.RunEditor = func(string, ...string) error { calls++; return nil }
		if code := runEditWithDeps([]string{outside, "--workflows-dir", dir}, deps); code != 1 || calls != 0 {
			t.Fatalf("outside path: code=%d editor calls=%d stderr=%s", code, calls, stderr.String())
		}
	})

	t.Run("broken relative path and symlink", func(t *testing.T) {
		dir := t.TempDir()
		broken := filepath.Join(dir, "broken.yml")
		if err := os.WriteFile(broken, []byte("broken: [\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, _ []byte) []byte { return validManageWorkflow("broken") })
		if code := runEditWithDeps([]string{"broken", "--workflows-dir", dir}, deps); code != 0 {
			t.Fatalf("edit broken by name: code=%d stderr=%s", code, stderr.String())
		}

		external := filepath.Join(t.TempDir(), "real.yml")
		writeManageWorkflow(t, external, "linked")
		link := filepath.Join(dir, "linked.yml")
		if err := os.Symlink(external, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		out.Reset()
		deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, body []byte) []byte {
			return bytes.Replace(body, []byte(`description: ""`), []byte(`description: "edited"`), 1)
		})
		if code := runEditWithDeps([]string{"linked.yml", "--workflows-dir", dir}, deps); code != 0 {
			t.Fatalf("edit symlink: code=%d stderr=%s", code, stderr.String())
		}
		info, err := os.Lstat(link)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink was not preserved: info=%v err=%v", info, err)
		}
		body, err := os.ReadFile(external)
		if err != nil || !bytes.Contains(body, []byte(`description: "edited"`)) {
			t.Fatalf("real file content=%s err=%v", body, err)
		}
	})

	t.Run("duplicate name requires path", func(t *testing.T) {
		dir := t.TempDir()
		writeManageWorkflow(t, filepath.Join(dir, "a.yml"), "same")
		writeManageWorkflow(t, filepath.Join(dir, "team", "a.yml"), "same")
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		calls := 0
		deps.RunEditor = func(string, ...string) error { calls++; return nil }
		if code := runEditWithDeps([]string{"same", "--workflows-dir", dir}, deps); code != 1 || calls != 0 {
			t.Fatalf("duplicate edit: code=%d editor calls=%d stderr=%s", code, calls, stderr.String())
		}
		want := "이름이 같은 워크플로우가 여러 개입니다: same (a.yml, team/a.yml). 파일 경로로 지정해주세요"
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("duplicate edit error = %s", stderr.String())
		}
	})

	t.Run("directory with workflow extension is not a target", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "folder.yml")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		deps := testWorkflowDeps(t, &out, &stderr)
		if code := runDeleteWithDeps([]string{"folder.yml", "--workflows-dir", dir, "--yes"}, deps); code != 1 {
			t.Fatalf("directory delete code=%d stderr=%s", code, stderr.String())
		}
		if info, err := os.Stat(target); err != nil || !info.IsDir() {
			t.Fatalf("directory target changed: info=%v err=%v", info, err)
		}
	})
}

func TestCopyWorkflow(t *testing.T) {
	dir := t.TempDir()
	original := []byte("# preserved\n\nname: 'source' # inline\ndescription: \"\"\nsteps: [{name: hello, run: echo hi}]\n")
	if err := os.WriteFile(filepath.Join(dir, "whatever.yml"), original, 0o640); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	deps := testWorkflowDeps(t, &out, &stderr)
	if code := runCopyWithDeps([]string{"--workflows-dir", dir, "source", "copy"}, deps); code != 0 {
		t.Fatalf("copy code=%d stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "copy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(original, []byte("'source'"), []byte("'copy'"), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("copied content = %q, want %q", got, want)
	}
	if mode := fileMode(t, filepath.Join(dir, "copy.yml")); mode != 0o640 {
		t.Fatalf("copy mode = %04o", mode)
	}
	stderr.Reset()
	if code := runCopyWithDeps([]string{"source", "copy", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "이미 있는 워크플로우") {
		t.Fatalf("duplicate copy: code=%d stderr=%s", code, stderr.String())
	}
	stderr.Reset()
	if code := runCopyWithDeps([]string{"missing", "new", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "찾을 수 없습니다") {
		t.Fatalf("missing source: code=%d stderr=%s", code, stderr.String())
	}

	var editCalls int
	deps.RunEditor, _ = fakeEditor(t, func(_ int, _ string, body []byte) []byte {
		editCalls++
		return bytes.Replace(body, []byte(`description: ""`), []byte(`description: "edited"`), 1)
	})
	out.Reset()
	if code := runCopyWithDeps([]string{"source", "edited", "--workflows-dir", dir, "--edit"}, deps); code != 0 {
		t.Fatalf("copy --edit: code=%d stderr=%s", code, stderr.String())
	}
	if editCalls != 1 || !strings.Contains(out.String(), "복사했습니다:") {
		t.Fatalf("copy --edit output=%s calls=%d", out.String(), editCalls)
	}

	dupDir := t.TempDir()
	writeManageWorkflow(t, filepath.Join(dupDir, "a.yml"), "same")
	writeManageWorkflow(t, filepath.Join(dupDir, "team", "a.yml"), "same")
	stderr.Reset()
	if code := runCopyWithDeps([]string{"same", "new", "--workflows-dir", dupDir}, deps); code != 1 {
		t.Fatalf("duplicate source copy code=%d stderr=%s", code, stderr.String())
	}
	wantDuplicate := "이름이 같은 워크플로우가 여러 개입니다: same (a.yml, team/a.yml). 중복을 먼저 정리해주세요"
	if !strings.Contains(stderr.String(), wantDuplicate) {
		t.Fatalf("duplicate source copy error = %s", stderr.String())
	}
}

func TestDeleteWorkflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.yml")
	writeManageWorkflow(t, path, "hello")
	var out, stderr bytes.Buffer
	deps := testWorkflowDeps(t, &out, &stderr)
	asked := ""
	deps.Confirm = func(question string) bool { asked = question; return false }
	if code := runDeleteWithDeps([]string{"hello", "--workflows-dir", dir}, deps); code != 1 || !strings.Contains(out.String(), "삭제하지 않았습니다") {
		t.Fatalf("declined delete: code=%d out=%s", code, out.String())
	}
	if asked != "워크플로우 hello 을 삭제할까요? (hello.yml)" {
		t.Fatalf("confirmation = %q", asked)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("declined delete removed file: %v", err)
	}
	if code := runDeleteWithDeps([]string{"--yes", "--workflows-dir", dir, "hello"}, deps); code != 0 {
		t.Fatalf("--yes delete code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deleted file remains: %v", err)
	}

	broken := filepath.Join(dir, "broken.yml")
	if err := os.WriteFile(broken, []byte("invalid: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps.Confirm = func(question string) bool {
		if question != "파일 broken.yml 을 삭제할까요?" {
			t.Errorf("broken confirmation = %q", question)
		}
		return true
	}
	if code := runDeleteWithDeps([]string{"broken.yml", "--workflows-dir", dir}, deps); code != 0 {
		t.Fatalf("delete broken code=%d stderr=%s", code, stderr.String())
	}

	external := filepath.Join(t.TempDir(), "real.yml")
	writeManageWorkflow(t, external, "linkwf")
	link := filepath.Join(dir, "linkwf.yml")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	out.Reset()
	if code := runDeleteWithDeps([]string{"linkwf.yml", "--workflows-dir", dir, "--yes"}, deps); code != 0 {
		t.Fatalf("delete symlink: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("link remains: %v", err)
	}
	if _, err := os.Stat(external); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
	if !strings.Contains(out.String(), "링크만 삭제했습니다:") {
		t.Fatalf("symlink output=%s", out.String())
	}

	dupDir := t.TempDir()
	writeManageWorkflow(t, filepath.Join(dupDir, "a.yml"), "same")
	writeManageWorkflow(t, filepath.Join(dupDir, "team", "a.yml"), "same")
	stderr.Reset()
	if code := runDeleteWithDeps([]string{"same", "--workflows-dir", dupDir, "--yes"}, deps); code != 1 {
		t.Fatalf("duplicate delete code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "이름이 같은 워크플로우가 여러 개입니다: same (a.yml, team/a.yml). 파일 경로로 지정해주세요") {
		t.Fatalf("duplicate delete error = %s", stderr.String())
	}
}

func TestListAndValidateWorkflowPathsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeManageWorkflow(t, filepath.Join(dir, "team", "deploy.yml"), "deploy")
	var out, stderr bytes.Buffer
	deps := testWorkflowDeps(t, &out, &stderr)
	if code := runListWithDeps([]string{"--workflows-dir", dir}, deps); code != 0 {
		t.Fatalf("list code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "워크플로우 디렉토리: "+dir) || !strings.Contains(out.String(), "파일") || !strings.Contains(out.String(), "team/deploy.yml") {
		t.Fatalf("list output=%s", out.String())
	}
	out.Reset()
	if code := runListWithDeps([]string{"--json", "--workflows-dir", dir}, deps); code != 0 {
		t.Fatalf("json list code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(out.String(), `"path": "`+filepath.Join(dir, "team", "deploy.yml")+`"`) || strings.Contains(out.String(), `"Path"`) {
		t.Fatalf("json list output=%s", out.String())
	}
	out.Reset()
	writeManageWorkflow(t, filepath.Join(dir, "other", "same.yml"), "deploy")
	if code := runListWithDeps([]string{"--json", "--workflows-dir", dir}, deps); code != 0 || !strings.Contains(stderr.String(), "중복") || !strings.Contains(stderr.String(), "team/deploy.yml") {
		t.Fatalf("duplicate JSON list: code=%d stderr=%s", code, stderr.String())
	}
	if code := runListWithDeps([]string{"--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "중복") || !strings.Contains(stderr.String(), "team/deploy.yml") {
		t.Fatalf("duplicate list: code=%d stderr=%s", code, stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if code := runValidateWithDeps([]string{"--workflows-dir", dir}, deps); code != 1 || !strings.Contains(out.String(), "OK    deploy  (other/same.yml)") || !strings.Contains(out.String(), "FAIL  중복 이름") {
		t.Fatalf("duplicate validate: code=%d out=%s stderr=%s", code, out.String(), stderr.String())
	}
	bad := filepath.Join(dir, "team", "bad.yml")
	if err := os.WriteFile(bad, []byte("name: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runListWithDeps([]string{"--workflows-dir", dir}, deps); code != 1 || !strings.Contains(stderr.String(), "team/bad.yml") || !strings.Contains(stderr.String(), "deplite-agent edit <파일>") {
		t.Fatalf("bad file list: code=%d stderr=%s", code, stderr.String())
	}

	empty := t.TempDir()
	out.Reset()
	stderr.Reset()
	if code := runListWithDeps([]string{"--workflows-dir", empty}, deps); code != 0 || out.String() != "워크플로우 디렉토리: "+empty+"\n\n워크플로우가 없습니다.\ndeplite-agent add <이름> 으로 만들 수 있습니다.\n" {
		t.Fatalf("empty list: code=%d out=%s stderr=%s", code, out.String(), stderr.String())
	}
}

func TestListServiceWorkflowHint(t *testing.T) {
	var out, stderr bytes.Buffer
	deps := testWorkflowDeps(t, &out, &stderr)
	deps.ReadServiceUnit = func() (*systemd.Info, error) {
		return &systemd.Info{WorkflowsDir: "/service/workflows"}, nil
	}
	if code := runListWithDeps(nil, deps); code != 0 {
		t.Fatalf("list code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "참고: 서비스는 /service/workflows") {
		t.Fatalf("service hint=%s", stderr.String())
	}

	deps.ReadServiceUnit = func() (*systemd.Info, error) { return nil, os.ErrPermission }
	if hint := workflowServiceHint("/cli/workflows", false, deps); hint != "" {
		t.Fatalf("unit read failure hint = %q", hint)
	}
}

func TestWorkflowDirectoryUsesExistingResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("DEPLITE_DATA_DIR", filepath.Join(home, "data"))
	t.Setenv("DEPLITE_WORKFLOWS_DIR", filepath.Join(home, "env-workflows"))

	dir, overridden, err := workflowDirectory("", false)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(filepath.Join(home, "env-workflows"))
	if dir != filepath.Clean(want) || !overridden {
		t.Fatalf("workflowDirectory() = %q, %v; want %q, true", dir, overridden, filepath.Clean(want))
	}
	dir, overridden, err = workflowDirectory(filepath.Join(home, "flag-workflows"), true)
	if err != nil {
		t.Fatal(err)
	}
	want, _ = filepath.Abs(filepath.Join(home, "flag-workflows"))
	if dir != filepath.Clean(want) || !overridden {
		t.Fatalf("flag workflowDirectory() = %q, %v; want %q, true", dir, overridden, filepath.Clean(want))
	}
}

func TestWorkflowCommandHelpText(t *testing.T) {
	var out, stderr bytes.Buffer
	deps := testWorkflowDeps(t, &out, &stderr)
	tests := []struct {
		name   string
		run    func([]string, workflowCmdDeps) int
		want   string
		editor bool
	}{
		{"add", runAddWithDeps, "새 워크플로우를 편집기로 작성합니다. 편집기를 닫으면 검사하고, 통과하면 워크플로우 디렉토리에 저장합니다.", true},
		{"edit", runEditWithDeps, "워크플로우를 편집기로 고칩니다. 편집기를 닫으면 검사하고, 통과하면 반영합니다. 읽지 못한 파일은 파일 경로로 지정할 수 있습니다.", true},
		{"cp", runCopyWithDeps, "워크플로우를 새 이름으로 복사합니다. name만 바꾸고 나머지 내용은 그대로 둡니다.", true},
		{"delete", runDeleteWithDeps, "워크플로우 파일을 삭제합니다.", false},
	}
	for _, test := range tests {
		out.Reset()
		stderr.Reset()
		if code := test.run([]string{"--help"}, deps); code != 2 {
			t.Fatalf("%s --help code = %d", test.name, code)
		}
		if !strings.Contains(stderr.String(), test.want) || !strings.Contains(stderr.String(), "워크플로우 디렉토리 (기본값: <data-dir>/workflows)") {
			t.Errorf("%s help = %s", test.name, stderr.String())
		}
		if test.editor && !strings.Contains(stderr.String(), "사용할 편집기 (기본값: $VISUAL, $EDITOR, editor, nano, vim, vi 순)") {
			t.Errorf("%s editor help = %s", test.name, stderr.String())
		}
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
