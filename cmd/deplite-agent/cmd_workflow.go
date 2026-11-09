package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Deplite/agent/internal/agent"
	"github.com/Deplite/agent/internal/apiclient"
	"github.com/Deplite/agent/internal/textutil"
	"github.com/Deplite/agent/internal/workflow"
)

func runValidate(args []string) int {
	return runValidateWithDeps(args, defaultWorkflowCmdDeps())
}

func runValidateWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("validate",
		"deplite-agent validate [--workflows-dir DIR] [FILE...]",
		"워크플로우 파일을 검사합니다. Agent를 실행하지 않고도 문법과 스키마를 확인할 수 있습니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	type outcome struct {
		path string
		name string
		err  error
	}
	var results []outcome
	directoryMode := false

	if files := fs.Args(); len(files) > 0 {
		for _, f := range files {
			wf, err := workflow.LoadFile(f)
			results = append(results, outcome{path: f, name: wf.Name, err: err})
		}
	} else {
		directoryMode = true
		dir, _, err := workflowDirectory(*workflowsDir, false)
		if err != nil {
			return workflowError(deps.Err, "%v", err)
		}
		if _, err := os.Stat(dir); err != nil {
			return workflowError(deps.Err, "워크플로우 디렉토리를 열 수 없습니다: %s", dir)
		}
		wfs, bad := workflow.Scan(dir)
		for _, w := range wfs {
			rel, _ := filepath.Rel(dir, w.Path)
			results = append(results, outcome{path: rel, name: w.Name})
		}
		for _, e := range bad {
			rel, _ := filepath.Rel(dir, e.Path)
			results = append(results, outcome{path: rel, err: e.Err})
		}
		if len(results) == 0 {
			fmt.Fprintf(deps.Out, "%s 에 워크플로우 파일이 없습니다.\n", dir)
			return 0
		}
	}

	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
			fmt.Fprintf(deps.Out, "FAIL  %s\n      %v\n", r.path, r.err)
			continue
		}
		if directoryMode {
			fmt.Fprintf(deps.Out, "OK    %s  (%s)\n", r.name, r.path)
		} else {
			fmt.Fprintf(deps.Out, "OK    %s\n", r.name)
		}
	}
	fmt.Fprintf(deps.Out, "\n정상 %d개, 오류 %d개\n", len(results)-failed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func runList(args []string) int {
	return runListWithDeps(args, defaultWorkflowCmdDeps())
}

func runListWithDeps(args []string, deps workflowCmdDeps) int {
	deps = completeWorkflowCmdDeps(deps)
	fs := newFlagSet("list",
		"deplite-agent list [--workflows-dir DIR] [--json]",
		"Agent가 인식한 워크플로우와 파일 위치를 보여줍니다. 대시보드에 보고되는 것과 같은 목록입니다.")
	fs.SetOutput(deps.Err)
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	asJSON := fs.Bool("json", false, "JSON으로 출력합니다")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	workflowsFlagSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "workflows-dir" {
			workflowsFlagSet = true
		}
	})
	dir, overridden, err := workflowDirectory(*workflowsDir, workflowsFlagSet)
	if err != nil {
		return workflowError(deps.Err, "%v", err)
	}
	if hint := workflowServiceHint(dir, overridden, deps); hint != "" {
		fmt.Fprintln(deps.Err, "참고: "+hint)
	}
	wfs, bad := workflow.Scan(dir)
	duplicates := duplicateNameGroups(bad)

	if *asJSON {
		items := make([]struct {
			workflow.Workflow
			Path string `json:"path"`
		}, 0, len(wfs))
		for _, wf := range wfs {
			items = append(items, struct {
				workflow.Workflow
				Path string `json:"path"`
			}{Workflow: wf, Path: wf.Path})
		}
		enc := json.NewEncoder(deps.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			return workflowError(deps.Err, "%v", err)
		}
		if len(duplicates) > 0 {
			printDuplicateWorkflows(deps.Err, duplicates, true)
		}
		return 0
	}

	fmt.Fprintf(deps.Out, "워크플로우 디렉토리: %s\n\n", dir)
	if len(wfs) == 0 && len(bad) == 0 {
		fmt.Fprintln(deps.Out, "워크플로우가 없습니다.")
		fmt.Fprintln(deps.Out, "deplite-agent add <이름> 으로 만들 수 있습니다.")
		return 0
	}

	var t textutil.Table
	t.Add("이름", "버전", "스텝", "파라미터", "시크릿", "외부 호출", "승인 방식", "파일")
	for _, wf := range wfs {
		t.Add(wf.Name, dash(wf.Version), fmt.Sprint(len(wf.Steps)),
			dash(paramNames(wf)), dash(strings.Join(wf.SecretNames(), ",")), callableNote(wf), dash(strings.Join(wf.ApprovalMethods(), ",")), relativeWorkflowPath(dir, wf.Path))
	}
	t.Render(deps.Out)

	if len(duplicates) > 0 {
		printDuplicateWorkflows(deps.Err, duplicates, false)
	}
	unread := unreadWorkflowErrors(bad)
	if len(unread) > 0 {
		printUnreadFiles(deps.Err, dir, unread)
	}
	if len(bad) > 0 {
		return 1
	}
	return 0
}

func printUnreadFiles(out io.Writer, dir string, bad []workflow.ScanError) {
	fmt.Fprintf(out, "\n읽지 못한 파일 %d개 (deplite-agent validate 로 확인해주세요)\n", len(bad))
	for _, entry := range bad {
		fmt.Fprintf(out, "  %s\n", relativeWorkflowPath(dir, entry.Path))
	}
	fmt.Fprintln(out, "고치려면 deplite-agent edit <파일> 을 사용해주세요.")
}

type duplicateNameGroup struct {
	name  string
	files []string
}

func duplicateNameGroups(bad []workflow.ScanError) []duplicateNameGroup {
	byName := make(map[string][]string)
	for _, entry := range bad {
		var duplicate *workflow.DuplicateNameError
		if errors.As(entry.Err, &duplicate) {
			byName[duplicate.Name] = duplicate.Files
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	groups := make([]duplicateNameGroup, 0, len(names))
	for _, name := range names {
		groups = append(groups, duplicateNameGroup{name: name, files: byName[name]})
	}
	return groups
}

func unreadWorkflowErrors(bad []workflow.ScanError) []workflow.ScanError {
	var unread []workflow.ScanError
	for _, entry := range bad {
		var duplicate *workflow.DuplicateNameError
		if !errors.As(entry.Err, &duplicate) {
			unread = append(unread, entry)
		}
	}
	return unread
}

func printDuplicateWorkflows(out io.Writer, groups []duplicateNameGroup, warning bool) {
	count := len(groups)
	if warning {
		fmt.Fprintf(out, "경고: 이름이 겹쳐 무효가 된 워크플로우 %d개 (파일을 하나만 남겨주세요)\n", count)
	} else {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "이름이 겹쳐 무효가 된 워크플로우 %d개 (파일을 하나만 남겨주세요)\n", count)
	}
	for _, group := range groups {
		fmt.Fprintf(out, "  %s: %s\n", group.name, strings.Join(group.files, ", "))
	}
}

func relativeWorkflowPath(dir, path string) string {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return path
	}
	return rel
}

func runRun(args []string) int {
	fs := newFlagSet("run",
		"deplite-agent run <워크플로우_이름> [--param k=v] [--secret k=v] [--dry-run]",
		"워크플로우를 이 머신에서 바로 실행합니다. 백엔드에는 아무것도 보고하지 않습니다.")
	workflowsDir := fs.String("workflows-dir", "", "워크플로우 디렉토리 (기본값: <data-dir>/workflows)")
	dataDir := fs.String("data-dir", "", "데이터 디렉토리 (로그 미러링 위치)")
	dryRun := fs.Bool("dry-run", false, "실행하지 않고 실행 계획만 출력합니다")
	debug := fs.Bool("debug", false, "verbose 스텝의 원본 출력까지 남깁니다")
	noMirror := fs.Bool("no-log-mirror", false, "로그를 파일로 남기지 않습니다")
	var params, secrets stringList
	fs.Var(&params, "param", "파라미터 값 (key=value, 여러 번 지정 가능)")
	fs.Var(&secrets, "secret", "시크릿 값 (key=value, 여러 번 지정 가능)")
	name, ok := parseOneArg(fs, args)
	if !ok {
		return 2
	}

	dir, wfDir, err := dirs(*dataDir, *workflowsDir)
	if err != nil {
		return errorf("%v", err)
	}
	wf, err := agent.LoadWorkflow(wfDir, name)
	if err != nil {
		return errorf("%v", err)
	}
	rawParams, err := agent.ParseKeyValues(params, "--param")
	if err != nil {
		return errorf("%v", err)
	}
	rawSecrets, err := agent.ParseKeyValues(secrets, "--secret")
	if err != nil {
		return errorf("%v", err)
	}
	supplied := agent.CoerceParams(wf, rawParams)
	bound := agent.LocalSecrets(wf, rawSecrets)

	if *dryRun {
		if err := agent.DryRun(wf, supplied, bound, os.Stdout); err != nil {
			return errorf("%v", err)
		}
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mirrorDir := dir
	if *noMirror {
		mirrorDir = ""
	}
	result := agent.RunLocal(ctx, wf, supplied, bound, agent.LocalRunOptions{
		DataDir: mirrorDir,
		Debug:   *debug,
		Out:     os.Stdout,
	})
	fmt.Printf("\n결과: %s (exit %d)\n", result.Status, result.ExitCode)
	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "%s\n", result.Error)
	}
	if result.Status != apiclient.JobSuccess {
		if result.ExitCode > 0 {
			return result.ExitCode
		}
		return 1
	}
	return 0
}

func paramNames(wf workflow.Workflow) string {
	out := make([]string, 0, len(wf.Params))
	for _, p := range wf.Params {
		if p.Required {
			out = append(out, p.Name+"*")
			continue
		}
		out = append(out, p.Name)
	}
	return strings.Join(out, ",")
}

func callableNote(wf workflow.Workflow) string {
	if !wf.Callable() {
		return "불가"
	}
	if wf.On.Webhook == nil || len(wf.On.Webhook.Refs) == 0 {
		return "허용"
	}
	return strings.Join(wf.On.Webhook.Refs, ",")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
