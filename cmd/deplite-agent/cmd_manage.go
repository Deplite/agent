package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/systemd"
	"github.com/Deplite/agent/internal/workflow"
)

type workflowCmdDeps struct {
	Out             io.Writer
	Err             io.Writer
	RunEditor       func(string, ...string) error
	IsTerminal      func() bool
	Ask             func(string, bool) bool
	Confirm         func(string) bool
	LookPath        func(string) (string, error)
	ReadServiceUnit func() (*systemd.Info, error)
}

func defaultWorkflowCmdDeps() workflowCmdDeps {
	return workflowCmdDeps{
		Out: os.Stdout, Err: os.Stderr, RunEditor: runWorkflowEditor,
		IsTerminal: func() bool {
			info, err := os.Stdin.Stat()
			return err == nil && info.Mode()&os.ModeCharDevice != 0
		},
		Ask: func(question string, defaultYes bool) bool {
			prompt := "[y/N]"
			if defaultYes {
				prompt = "[Y/n]"
			}
			fmt.Fprintf(os.Stdout, "%s %s: ", question, prompt)
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return false
			}
			answer := strings.ToLower(strings.TrimSpace(line))
			if answer == "" {
				return defaultYes
			}
			return answer == "y" || answer == "yes"
		},
		Confirm: confirm, LookPath: exec.LookPath,
		ReadServiceUnit: func() (*systemd.Info, error) {
			if runtime.GOOS != "linux" {
				return nil, nil
			}
			return systemd.ReadUnit(systemd.UnitPath, systemd.OSOps{})
		},
	}
}

func completeWorkflowCmdDeps(deps workflowCmdDeps) workflowCmdDeps {
	defaults := defaultWorkflowCmdDeps()
	if deps.Out == nil {
		deps.Out = defaults.Out
	}
	if deps.Err == nil {
		deps.Err = defaults.Err
	}
	if deps.RunEditor == nil {
		deps.RunEditor = defaults.RunEditor
	}
	if deps.IsTerminal == nil {
		deps.IsTerminal = defaults.IsTerminal
	}
	if deps.Ask == nil {
		deps.Ask = defaults.Ask
	}
	if deps.Confirm == nil {
		deps.Confirm = defaults.Confirm
	}
	if deps.LookPath == nil {
		deps.LookPath = defaults.LookPath
	}
	if deps.ReadServiceUnit == nil {
		deps.ReadServiceUnit = defaults.ReadServiceUnit
	}
	return deps
}

func runWorkflowEditor(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGQUIT)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-signals:
			case <-done:
				return
			}
		}
	}()
	err := cmd.Run()
	signal.Stop(signals)
	close(done)
	<-stopped
	return err
}

func workflowDirectory(flagValue string, flagSet bool) (string, bool, error) {
	_, dir, err := dirs("", flagValue)
	if err != nil {
		return "", false, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false, err
	}
	overridden := flagSet || os.Getenv("DEPLITE_WORKFLOWS_DIR") != "" || os.Getenv("DEPLITE_DATA_DIR") != ""
	return filepath.Clean(abs), overridden, nil
}

func workflowServiceHint(dir string, overridden bool, deps workflowCmdDeps) string {
	if overridden || deps.ReadServiceUnit == nil {
		return ""
	}
	info, err := deps.ReadServiceUnit()
	if err != nil {
		return ""
	}
	return systemd.WorkflowsDirHint(info, dir)
}

func workflowError(out io.Writer, format string, args ...any) int {
	fmt.Fprintf(out, "오류: "+format+"\n", args...)
	return 1
}

func checkWorkflowDirectory(dir string) error {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("워크플로우 디렉토리가 없습니다: %s", dir)
	}
	return nil
}

func validWorkflowName(name string) error {
	if !workflow.ValidName(name) {
		return fmt.Errorf("워크플로우 이름은 영문, 숫자, _, ., - 로 1~128자여야 합니다: %q", name)
	}
	return nil
}

func runAdd(args []string) int { return runAddWithDeps(args, defaultWorkflowCmdDeps()) }

func runAddWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("add", "deplite-agent add <이름> [--workflows-dir DIR] [--editor CMD]", "새 워크플로우를 편집기로 작성합니다. 편집기를 닫으면 검사하고, 통과하면 워크플로우 디렉토리에 저장합니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	editorArg := fs.String("editor", "", "사용할 편집기 (기본값: $VISUAL, $EDITOR, editor, nano, vim, vi 순)")
	positional, ok := parseArgs(fs, args, 1)
	if !ok {
		return 2
	}
	editorSet := hasFlag(fs, "editor")
	dir, overridden, err := workflowDirectory(*workflowsDir, hasFlag(fs, "workflows-dir"))
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if hint := workflowServiceHint(dir, overridden, deps); hint != "" {
		return workflowError(deps.Err, "%s", hint)
	}
	if err := checkWorkflowDirectory(dir); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	name := positional[0]
	if err := validWorkflowName(name); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if err := checkNewWorkflowTarget(dir, name); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if !deps.IsTerminal() {
		return workflowError(deps.Err, "편집기를 열려면 터미널에서 실행해주세요")
	}
	editor, err := preflightEditor(*editorArg, editorSet, deps)
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	template := []byte(fmt.Sprintf("name: %s\ndescription: \"\"\nsteps:\n  - name: hello\n    run: |\n      echo \"hello\"\n", workflow.NameScalar(name)))
	buffer, err := createEditBuffer(name, template)
	if err != nil {
		return workflowError(deps.Err, "편집 버퍼를 만들지 못했습니다: %v", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(buffer)
		}
	}()
	validate := func(body []byte) error {
		wf, err := workflow.Parse(body)
		if err != nil {
			return err
		}
		if wf.Name != name {
			return fmt.Errorf("name 을 %q 으로 두어야 합니다 (지금은 %q)", name, wf.Name)
		}
		return checkDuplicateName(dir, name, "")
	}
	body, code := runEditLoop(buffer, template, editor, deps, func(body []byte) (bool, error) {
		if bytes.Equal(body, template) {
			return false, errUnchangedAdd
		}
		return true, validate(body)
	})
	if code != 0 {
		cleanup = false
		return code
	}
	if body == nil {
		return 1
	}
	path := filepath.Join(dir, name+".yml")
	if err := atomicCreateWorkflow(dir, path, body, 0o644); err != nil {
		cleanup = false
		return failWithBuffer(deps, buffer, template, err)
	}
	printWorkflowSaved(deps.Out, "저장했습니다", path)
	return 0
}

var errUnchangedAdd = errors.New("내용이 바뀌지 않아 워크플로우를 만들지 않았습니다.")

func runEdit(args []string) int { return runEditWithDeps(args, defaultWorkflowCmdDeps()) }

func runEditWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("edit", "deplite-agent edit <이름|파일> [--workflows-dir DIR] [--editor CMD]", "워크플로우를 편집기로 고칩니다. 편집기를 닫으면 검사하고, 통과하면 반영합니다. 읽지 못한 파일은 파일 경로로 지정할 수 있습니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	editorArg := fs.String("editor", "", "사용할 편집기 (기본값: $VISUAL, $EDITOR, editor, nano, vim, vi 순)")
	positional, ok := parseArgs(fs, args, 1)
	if !ok {
		return 2
	}
	dir, overridden, err := workflowDirectory(*workflowsDir, hasFlag(fs, "workflows-dir"))
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if hint := workflowServiceHint(dir, overridden, deps); hint != "" {
		return workflowError(deps.Err, "%s", hint)
	}
	if err := checkWorkflowDirectory(dir); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	target, originalName, err := resolveWorkflowTarget(dir, positional[0])
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if !deps.IsTerminal() {
		return workflowError(deps.Err, "편집기를 열려면 터미널에서 실행해주세요")
	}
	editor, err := preflightEditor(*editorArg, hasFlag(fs, "editor"), deps)
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	initial, err := os.ReadFile(target)
	if err != nil {
		return workflowError(deps.Err, "워크플로우 파일을 읽지 못했습니다: %v", err)
	}
	buffer, err := createEditBuffer(bufferName(originalName, target), initial)
	if err != nil {
		return workflowError(deps.Err, "편집 버퍼를 만들지 못했습니다: %v", err)
	}
	actualAtStart, err := filepath.EvalSymlinks(target)
	if err != nil {
		_ = os.Remove(buffer)
		return workflowError(deps.Err, "워크플로우 실제 경로를 확인하지 못했습니다: %v", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(buffer)
		}
	}()
	validate := func(body []byte) error {
		wf, err := workflow.Parse(body)
		if err != nil {
			return err
		}
		if originalName != "" && wf.Name != originalName {
			return fmt.Errorf("이름은 바꿀 수 없습니다 (원래 %q, 지금 %q). 새 이름이 필요하면 deplite-agent cp 로 복사한 뒤 delete 해주세요", originalName, wf.Name)
		}
		return checkDuplicateName(dir, wf.Name, target)
	}
	body, code := runEditLoop(buffer, initial, editor, deps, func(body []byte) (bool, error) {
		if bytes.Equal(body, initial) {
			return false, errNoEditChanges
		}
		return true, validate(body)
	})
	if code != 0 {
		cleanup = false
		return code
	}
	if body == nil {
		return 0
	}
	actualNow, pathErr := filepath.EvalSymlinks(target)
	current, readErr := os.ReadFile(target)
	if pathErr != nil || filepath.Clean(actualNow) != filepath.Clean(actualAtStart) || readErr != nil || !bytes.Equal(current, initial) {
		cleanup = false
		return failWithBuffer(deps, buffer, initial, fmt.Errorf("편집하는 동안 %s 가 바뀌었습니다", target))
	}
	if err := atomicReplaceWorkflow(target, body); err != nil {
		cleanup = false
		return failWithBuffer(deps, buffer, initial, err)
	}
	printWorkflowSaved(deps.Out, "저장했습니다", target)
	return 0
}

var errNoEditChanges = errors.New("변경 사항이 없습니다.")

func runCopy(args []string) int { return runCopyWithDeps(args, defaultWorkflowCmdDeps()) }

func runCopyWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("cp", "deplite-agent cp <원본_이름> <새_이름> [--workflows-dir DIR] [--edit] [--editor CMD]", "워크플로우를 새 이름으로 복사합니다. name만 바꾸고 나머지 내용은 그대로 둡니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	edit := fs.Bool("edit", false, "복사하기 전에 내용을 편집합니다")
	editorArg := fs.String("editor", "", "사용할 편집기 (기본값: $VISUAL, $EDITOR, editor, nano, vim, vi 순)")
	positional, ok := parseArgs(fs, args, 2)
	if !ok {
		return 2
	}
	dir, overridden, err := workflowDirectory(*workflowsDir, hasFlag(fs, "workflows-dir"))
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if hint := workflowServiceHint(dir, overridden, deps); hint != "" {
		return workflowError(deps.Err, "%s", hint)
	}
	if err := checkWorkflowDirectory(dir); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	source, err := loadWorkflowForCopy(dir, positional[0])
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	newName := positional[1]
	if err := validWorkflowName(newName); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if err := checkNewWorkflowTarget(dir, newName); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	original, err := os.ReadFile(source.Path)
	if err != nil {
		return workflowError(deps.Err, "워크플로우 파일을 읽지 못했습니다: %v", err)
	}
	copyBody, err := workflow.SetName(original, newName)
	if err != nil {
		return workflowError(deps.Err, "name 필드를 바꾸지 못했습니다: %v", err)
	}
	stat, err := os.Stat(source.Path)
	if err != nil {
		return workflowError(deps.Err, "워크플로우 파일을 확인하지 못했습니다: %v", err)
	}
	path := filepath.Join(dir, newName+".yml")
	withEditor := *edit || hasFlag(fs, "editor")
	var body []byte
	var buffer string
	cleanup := true
	if withEditor {
		if !deps.IsTerminal() {
			return workflowError(deps.Err, "편집기를 열려면 터미널에서 실행해주세요")
		}
	}
	editor := editorCommand{}
	if withEditor {
		editor, err = preflightEditor(*editorArg, hasFlag(fs, "editor"), deps)
		if err != nil {
			return workflowError(deps.Err, "%v", err)
		}
	}
	var code int
	if withEditor {
		buffer, err = createEditBuffer(newName, copyBody)
		if err != nil {
			return workflowError(deps.Err, "편집 버퍼를 만들지 못했습니다: %v", err)
		}
		defer func() {
			if cleanup {
				_ = os.Remove(buffer)
			}
		}()
		body, code = runEditLoop(buffer, copyBody, editor, deps, func(body []byte) (bool, error) {
			wf, err := workflow.Parse(body)
			if err != nil {
				return true, err
			}
			if wf.Name != newName {
				return true, fmt.Errorf("name 을 %q 으로 두어야 합니다 (지금은 %q)", newName, wf.Name)
			}
			return true, checkDuplicateName(dir, newName, "")
		})
		if code != 0 {
			cleanup = false
			return code
		}
	} else {
		body = copyBody
		if _, err := workflow.Parse(body); err != nil {
			return workflowError(deps.Err, "검사에 실패했습니다: %v", err)
		}
		if err := checkDuplicateName(dir, newName, ""); err != nil {
			return workflowError(deps.Err, "검사에 실패했습니다: %v", err)
		}
	}
	if err := atomicCreateWorkflow(dir, path, body, stat.Mode().Perm()); err != nil {
		if withEditor {
			cleanup = false
			return failWithBuffer(deps, buffer, copyBody, err)
		}
		return workflowError(deps.Err, "%v", err)
	}
	printWorkflowSaved(deps.Out, "복사했습니다", path)
	return 0
}

func runDelete(args []string) int { return runDeleteWithDeps(args, defaultWorkflowCmdDeps()) }

func runDeleteWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("delete", "deplite-agent delete <이름|파일> [--workflows-dir DIR] [--yes]", "워크플로우 파일을 삭제합니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	yes := fs.Bool("yes", false, "삭제를 확인 없이 진행합니다")
	positional, ok := parseArgs(fs, args, 1)
	if !ok {
		return 2
	}
	dir, overridden, err := workflowDirectory(*workflowsDir, hasFlag(fs, "workflows-dir"))
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if hint := workflowServiceHint(dir, overridden, deps); hint != "" {
		return workflowError(deps.Err, "%s", hint)
	}
	if err := checkWorkflowDirectory(dir); err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	target, originalName, err := resolveWorkflowTarget(dir, positional[0])
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if !*yes {
		question := fmt.Sprintf("파일 %s 을 삭제할까요?", relativeWorkflowPath(dir, target))
		if originalName != "" {
			question = fmt.Sprintf("워크플로우 %s 을 삭제할까요? (%s)", originalName, relativeWorkflowPath(dir, target))
		}
		if deps.Confirm == nil || !deps.Confirm(question) {
			fmt.Fprintln(deps.Out, "삭제하지 않았습니다.")
			return 1
		}
	}
	linkTarget, isLink := "", false
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		isLink = true
		linkTarget, _ = os.Readlink(target)
		if resolved, err := filepath.EvalSymlinks(target); err == nil {
			linkTarget = resolved
		} else if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(filepath.Dir(target), linkTarget)
		}
	}
	if err := os.Remove(target); err != nil {
		return workflowError(deps.Err, "워크플로우를 삭제하지 못했습니다: %v", err)
	}
	if isLink {
		fmt.Fprintf(deps.Out, "링크만 삭제했습니다: %s (원본 %s 는 그대로 있습니다)\n", target, linkTarget)
	} else {
		fmt.Fprintf(deps.Out, "삭제했습니다: %s\n", target)
	}
	fmt.Fprintln(deps.Out, "실행 중인 Agent는 재시작 없이 변경을 반영합니다.")
	return 0
}

func hasFlag(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func preflightEditor(editorArg string, editorSet bool, deps workflowCmdDeps) (editorCommand, error) {
	lookup := deps.LookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	type candidate struct {
		value  string
		strict bool
	}
	var candidates []candidate
	if editorSet {
		candidates = append(candidates, candidate{value: editorArg, strict: true})
	} else {
		if visual := os.Getenv("VISUAL"); visual != "" {
			candidates = append(candidates, candidate{value: visual})
		}
		if editor := os.Getenv("EDITOR"); editor != "" {
			candidates = append(candidates, candidate{value: editor})
		}
	}
	firstConfigured := ""
	for _, item := range candidates {
		fields := strings.Fields(item.value)
		if len(fields) == 0 {
			if item.strict {
				return editorCommand{}, fmt.Errorf("편집기를 찾지 못했습니다. --editor 로 지정해주세요")
			}
			continue
		}
		if firstConfigured == "" {
			firstConfigured = fields[0]
		}
		path, err := lookup(fields[0])
		if err == nil {
			return editorCommand{path: path, args: fields[1:]}, nil
		}
		if item.strict {
			return editorCommand{}, fmt.Errorf("편집기를 찾지 못했습니다: %s. --editor 로 지정해주세요", fields[0])
		}
	}
	for _, name := range []string{"editor", "nano", "vim", "vi"} {
		path, err := lookup(name)
		if err == nil {
			return editorCommand{path: path}, nil
		}
	}
	if firstConfigured != "" {
		return editorCommand{}, fmt.Errorf("편집기를 찾지 못했습니다: %s. --editor 로 지정해주세요", firstConfigured)
	}
	return editorCommand{}, fmt.Errorf("편집기를 찾지 못했습니다. --editor 로 지정해주세요")
}

type editorCommand struct {
	path string
	args []string
}

func createEditBuffer(name string, body []byte) (string, error) {
	if !workflow.ValidName(name) {
		name = "workflow"
	}
	f, err := os.CreateTemp("", "deplite-agent-"+name+"-*.yml")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func runEditLoop(buffer string, initial []byte, editor editorCommand, deps workflowCmdDeps, check func([]byte) (bool, error)) ([]byte, int) {
	run := deps.RunEditor
	if run == nil {
		run = runWorkflowEditor
	}
	for {
		args := append(append([]string(nil), editor.args...), buffer)
		if err := run(editor.path, args...); err != nil {
			return nil, failWithBuffer(deps, buffer, initial, fmt.Errorf("편집기가 오류로 끝나 저장하지 않았습니다: %v", err))
		}
		body, err := os.ReadFile(buffer)
		if err != nil {
			return nil, failWithBuffer(deps, buffer, initial, fmt.Errorf("편집 버퍼를 읽지 못했습니다: %v", err))
		}
		if len(bytes.TrimSpace(body)) == 0 {
			fmt.Fprintln(deps.Err, "내용이 비어 있어 저장하지 않았습니다.")
			_ = os.Remove(buffer)
			return nil, 1
		}
		accept, err := check(body)
		if err == nil && accept {
			return body, 0
		}
		if errors.Is(err, errUnchangedAdd) {
			fmt.Fprintln(deps.Err, err.Error())
			_ = os.Remove(buffer)
			return nil, 1
		}
		if errors.Is(err, errNoEditChanges) {
			fmt.Fprintln(deps.Out, err.Error())
			removeBufferIfUnchanged(buffer, initial)
			return nil, 0
		}
		fmt.Fprintf(deps.Err, "검사에 실패했습니다: %v\n", err)
		if deps.Ask != nil && deps.Ask("다시 편집할까요?", true) {
			continue
		}
		fmt.Fprintln(deps.Err, "저장하지 않았습니다.")
		preserveBuffer(deps.Err, buffer, initial)
		return nil, 1
	}
}

func failWithBuffer(deps workflowCmdDeps, buffer string, initial []byte, err error) int {
	workflowError(deps.Err, "%v", err)
	preserveBuffer(deps.Err, buffer, initial)
	return 1
}

func preserveBuffer(out io.Writer, buffer string, initial []byte) {
	body, err := os.ReadFile(buffer)
	if err == nil && !bytes.Equal(body, initial) {
		fmt.Fprintf(out, "작성한 내용은 %s 에 남겨두었습니다.\n", buffer)
		return
	}
	_ = os.Remove(buffer)
}

func removeBufferIfUnchanged(buffer string, initial []byte) {
	body, err := os.ReadFile(buffer)
	if err != nil || bytes.Equal(body, initial) {
		_ = os.Remove(buffer)
	}
}

func bufferName(name, path string) string {
	if workflow.ValidName(name) {
		return name
	}
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

func checkNewWorkflowTarget(dir, name string) error {
	wfs, bad := workflow.Scan(dir)
	if paths := workflowNameFiles(dir, wfs, bad)[name]; len(paths) > 0 {
		if len(paths) > 1 {
			return fmt.Errorf("이름이 같은 워크플로우가 이미 여러 개 있습니다: %s (%s). 중복을 먼저 정리해주세요", name, strings.Join(paths, ", "))
		}
		return fmt.Errorf("이미 있는 워크플로우입니다: %s (%s). 고치려면 deplite-agent edit %s 을 사용해주세요", name, strings.Join(paths, ", "), name)
	}
	for _, ext := range []string{".yml", ".yaml"} {
		path := filepath.Join(dir, name+ext)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("파일이 이미 있습니다: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("파일을 확인하지 못했습니다: %v", err)
		}
	}
	return nil
}

func checkDuplicateName(dir, name, exclude string) error {
	wfs, bad := workflow.Scan(dir)
	files := workflowNameFiles(dir, wfs, bad)[name]
	paths := make([]string, 0)
	for _, file := range files {
		path := filepath.Join(dir, filepath.FromSlash(file))
		if !sameWorkflowPath(dir, path, exclude) {
			paths = append(paths, file)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return fmt.Errorf("같은 이름의 워크플로우가 이미 있습니다: %s", strings.Join(paths, ", "))
}

func sameWorkflowPath(dir, left, right string) bool {
	if right == "" {
		return false
	}
	leftAbs, err1 := filepath.Abs(left)
	rightAbs, err2 := filepath.Abs(right)
	if err1 != nil || err2 != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

func resolveWorkflowTarget(dir, arg string) (string, string, error) {
	wfs, bad := workflow.Scan(dir)
	filesByName := workflowNameFiles(dir, wfs, bad)
	if paths := filesByName[arg]; len(paths) > 1 {
		return "", "", duplicateWorkflowNameError(arg, paths, false)
	}
	for _, wf := range wfs {
		if wf.Name == arg {
			return wf.Path, wf.Name, nil
		}
	}
	if workflow.ValidName(arg) {
		for _, ext := range []string{".yml", ".yaml"} {
			candidate := filepath.Join(dir, arg+ext)
			for _, entry := range bad {
				if sameWorkflowPath(dir, candidate, entry.Path) {
					return candidate, "", nil
				}
			}
		}
	}
	ext := strings.ToLower(filepath.Ext(arg))
	if ext == ".yml" || ext == ".yaml" {
		candidate := arg
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		candidate, _ = filepath.Abs(filepath.Clean(candidate))
		rel, relErr := filepath.Rel(dir, candidate)
		inside := relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
		if inside {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				if duplicateNameForPath(dir, bad, candidate) != "" {
					return candidate, "", nil
				}
				wf, err := workflow.LoadFile(candidate)
				if err == nil {
					return candidate, wf.Name, nil
				}
				return candidate, "", nil
			}
		}
	}
	_, err := agent.LoadWorkflow(dir, arg)
	return "", "", err
}

func loadWorkflowForCopy(dir, name string) (workflow.Workflow, error) {
	wfs, bad := workflow.Scan(dir)
	if paths := workflowNameFiles(dir, wfs, bad)[name]; len(paths) > 1 {
		return workflow.Workflow{}, duplicateWorkflowNameError(name, paths, true)
	}
	for _, wf := range wfs {
		if wf.Name == name {
			return wf, nil
		}
	}
	return agent.LoadWorkflow(dir, name)
}

func duplicateWorkflowNameError(name string, paths []string, copying bool) error {
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	message := fmt.Sprintf("이름이 같은 워크플로우가 여러 개입니다: %s (%s). ", name, strings.Join(paths, ", "))
	if copying {
		message += "중복을 먼저 정리해주세요"
	} else {
		message += "파일 경로로 지정해주세요"
	}
	return errors.New(message)
}

func workflowNameFiles(dir string, wfs []workflow.Workflow, bad []workflow.ScanError) map[string][]string {
	files := make(map[string][]string)
	for _, wf := range wfs {
		files[wf.Name] = append(files[wf.Name], filepath.ToSlash(relativeWorkflowPath(dir, wf.Path)))
	}
	for _, entry := range bad {
		var duplicate *workflow.DuplicateNameError
		if errors.As(entry.Err, &duplicate) {
			files[duplicate.Name] = append([]string(nil), duplicate.Files...)
		}
	}
	for name := range files {
		sort.Strings(files[name])
	}
	return files
}

func duplicateNameForPath(dir string, bad []workflow.ScanError, path string) string {
	for _, entry := range bad {
		var duplicate *workflow.DuplicateNameError
		if errors.As(entry.Err, &duplicate) && sameWorkflowPath(dir, entry.Path, path) {
			return duplicate.Name
		}
	}
	return ""
}

func atomicCreateWorkflow(dir, target string, body []byte, mode os.FileMode) error {
	tmp, file, err := openWorkflowTemp(dir, mode.Perm())
	if err != nil {
		return fmt.Errorf("임시 파일을 만들지 못했습니다: %w", err)
	}
	defer os.Remove(tmp)
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return fmt.Errorf("파일을 쓰지 못했습니다: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("파일을 저장하지 못했습니다: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("파일을 닫지 못했습니다: %w", err)
	}
	if err := os.Link(tmp, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("파일이 이미 있습니다: %s", target)
		}
		return fmt.Errorf("파일을 만들지 못했습니다: %w", err)
	}
	return nil
}

func openWorkflowTemp(dir string, mode os.FileMode) (string, *os.File, error) {
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf(".deplite-agent-%d-%d.tmp", os.Getpid(), time.Now().UnixNano()+int64(i))
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return path, file, err
	}
	return "", nil, errors.New("임시 파일 이름을 확보하지 못했습니다")
}

func atomicReplaceWorkflow(target string, body []byte) error {
	actual, err := filepath.EvalSymlinks(target)
	if err != nil {
		return fmt.Errorf("워크플로우 실제 경로를 확인하지 못했습니다: %w", err)
	}
	info, err := os.Stat(actual)
	if err != nil {
		return fmt.Errorf("워크플로우 파일을 확인하지 못했습니다: %w", err)
	}
	tmp, file, err := openWorkflowTemp(filepath.Dir(actual), 0o600)
	if err != nil {
		return fmt.Errorf("임시 파일을 만들지 못했습니다: %w", err)
	}
	defer os.Remove(tmp)
	if err := file.Chmod(info.Mode().Perm()); err != nil {
		_ = file.Close()
		return fmt.Errorf("파일 권한을 설정하지 못했습니다: %w", err)
	}
	if os.Geteuid() == 0 {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmp, int(stat.Uid), int(stat.Gid))
		}
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return fmt.Errorf("파일을 쓰지 못했습니다: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("파일을 저장하지 못했습니다: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("파일을 닫지 못했습니다: %w", err)
	}
	if err := os.Rename(tmp, actual); err != nil {
		return fmt.Errorf("파일을 바꾸지 못했습니다: %w", err)
	}
	return nil
}

func printWorkflowSaved(out io.Writer, verb, path string) {
	fmt.Fprintf(out, "%s: %s\n", verb, path)
	fmt.Fprintln(out, "실행 중인 Agent는 재시작 없이 변경을 반영합니다.")
}
