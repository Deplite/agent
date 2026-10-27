package systemd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type fakeOps struct {
	dirs        map[string]bool
	files       map[string][]byte
	lookErr     map[string]error
	runErr      map[string]error
	runOutput   map[string][]byte
	runs        []string
	events      []string
	createdDirs []string
	written     map[string][]byte
	tempData    []byte
	removed     []string
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		dirs:  map[string]bool{"/run/systemd/system": true},
		files: map[string][]byte{}, lookErr: map[string]error{}, runErr: map[string]error{},
		runOutput: map[string][]byte{}, written: map[string][]byte{},
	}
}

func (f *fakeOps) IsDir(path string) bool { return f.dirs[path] }

func (f *fakeOps) LookPath(name string) (string, error) {
	if err := f.lookErr[name]; err != nil {
		return "", err
	}
	return "/usr/bin/" + name, nil
}

func (f *fakeOps) ReadFile(path string) ([]byte, error) {
	body, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), body...), nil
}

func (f *fakeOps) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	f.runs = append(f.runs, call)
	f.events = append(f.events, "run:"+call)
	return f.runOutput[call], f.runErr[call]
}

func (f *fakeOps) WriteFile(path string, body []byte, _ os.FileMode) error {
	f.written[path] = append([]byte(nil), body...)
	f.events = append(f.events, "write:"+path)
	return nil
}

func (f *fakeOps) CreateTemp(body []byte) (string, func(), error) {
	f.tempData = append([]byte(nil), body...)
	f.events = append(f.events, "temp")
	return "/tmp/deplite-agent.service.temp", func() { f.events = append(f.events, "temp-cleanup") }, nil
}

func (f *fakeOps) MkdirAll(path string, _ os.FileMode) error {
	f.createdDirs = append(f.createdDirs, path)
	f.events = append(f.events, "mkdir:"+path)
	return nil
}

func (f *fakeOps) Chown(path string, _, _ int) error {
	f.events = append(f.events, "chown:"+path)
	return nil
}

func (f *fakeOps) Remove(path string) error {
	f.removed = append(f.removed, path)
	f.events = append(f.events, "remove:"+path)
	return nil
}

func validConfig(euid int) Config {
	user := "alice"
	if euid == 0 {
		user = "root"
	}
	return Config{
		GOOS: "linux", EUID: euid, UID: euid, GID: euid, User: user,
		Executable:   "/usr/local/bin/deplite-agent",
		DataDir:      "/home/alice/.config/deplite-agent",
		WorkflowsDir: "/home/alice/.config/deplite-agent/workflows",
		UnitPath:     "/etc/systemd/system/deplite-agent.service",
	}
}

func TestRenderUnit(t *testing.T) {
	for _, user := range []string{"root", "alice"} {
		t.Run(user, func(t *testing.T) {
			got, err := RenderUnit(UnitConfig{
				User: user, Executable: "/opt/deplite-agent",
				DataDir: "/var/lib/deplite-agent", WorkflowsDir: "/var/lib/deplite-agent/workflows",
			})
			if err != nil {
				t.Fatal(err)
			}
			want := "[Unit]\nDescription=Deplite Agent\nWants=network-online.target\nAfter=network-online.target\n\n" +
				"[Service]\nType=simple\nUser=" + user + "\n" +
				"Environment=DEPLITE_DATA_DIR=/var/lib/deplite-agent\n" +
				"Environment=DEPLITE_WORKFLOWS_DIR=/var/lib/deplite-agent/workflows\n" +
				"EnvironmentFile=-/var/lib/deplite-agent/agent.env\n" +
				"ExecStart=/opt/deplite-agent start\nRestart=always\nRestartSec=5\n\n" +
				"[Install]\nWantedBy=multi-user.target\n"
			if string(got) != want {
				t.Fatalf("unit mismatch:\n%s", got)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	for _, path := range []string{"relative/path", "/has space", "/has\"quote", "/has\\slash", "/has%specifier", "/has\nnewline"} {
		t.Run(path, func(t *testing.T) {
			if err := ValidatePath(path); err == nil {
				t.Fatalf("ValidatePath(%q) succeeded", path)
			}
		})
	}
	if err := ValidatePath("/var/lib/deplite-agent"); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareExistingUnit(t *testing.T) {
	config := validConfig(0)
	want, err := RenderUnit(UnitConfig{User: config.User, Executable: config.Executable, DataDir: config.DataDir, WorkflowsDir: config.WorkflowsDir})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		body        []byte
		yes         bool
		confirm     func(string) bool
		wantErr     error
		wantAsk     int
		wantOldInfo bool
	}{
		{name: "same", body: want, wantAsk: 0},
		{name: "different and confirmed", body: []byte("[Service]\nUser=old\nEnvironment=DEPLITE_DATA_DIR=/old\nExecStart=/old/agent start\n"), confirm: func(string) bool { return true }, wantAsk: 1, wantOldInfo: true},
		{name: "different and yes", body: []byte("[Service]\nUser=old\nEnvironment=DEPLITE_DATA_DIR=/old\nEnvironment=DEPLITE_WORKFLOWS_DIR=/old/workflows\nExecStart=/old/agent start\n"), yes: true, wantAsk: 0, wantOldInfo: true},
		{name: "declined", body: []byte("[Service]\nUser=old\nEnvironment=DEPLITE_DATA_DIR=/old\nEnvironment=DEPLITE_WORKFLOWS_DIR=/old/workflows\nExecStart=/old/agent start\n"), confirm: func(string) bool { return false }, wantErr: ErrReplaceDeclined, wantAsk: 1, wantOldInfo: true},
		{name: "noninteractive", body: []byte("[Service]\nUser=old\nEnvironment=DEPLITE_DATA_DIR=/old\nEnvironment=DEPLITE_WORKFLOWS_DIR=/old/workflows\nExecStart=/old/agent start\n"), wantErr: ErrConfirmNeeded, wantOldInfo: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeOps()
			ops.files[config.UnitPath] = tc.body
			config.Yes = tc.yes
			asks := 0
			confirm := tc.confirm
			if confirm != nil {
				confirm = func(question string) bool {
					asks++
					return tc.confirm(question)
				}
			}
			var out bytes.Buffer
			plan, err := Prepare(context.Background(), config, ops, &out, confirm)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Prepare error = %v, want %v", err, tc.wantErr)
			}
			if asks != tc.wantAsk {
				t.Fatalf("confirm called %d times, want %d", asks, tc.wantAsk)
			}
			if tc.wantOldInfo && (!strings.Contains(out.String(), "User=old") || !strings.Contains(out.String(), "ExecStart=/old/agent start")) {
				t.Fatalf("existing service values were not shown: %s", out.String())
			}
			if err == nil && (plan == nil || !plan.UnitExisting) {
				t.Fatal("expected a service plan for existing unit")
			}
		})
	}
}

func TestPrepareRejectsMissingPrerequisites(t *testing.T) {
	config := validConfig(1000)
	ops := newFakeOps()
	ops.lookErr["systemctl"] = errors.New("not found")
	if _, err := Prepare(context.Background(), config, ops, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("Prepare succeeded without systemctl")
	}
	if len(ops.runs) != 0 {
		t.Fatalf("commands ran before prerequisite failure: %v", ops.runs)
	}

	config = validConfig(1000)
	ops = newFakeOps()
	ops.lookErr["sudo"] = errors.New("not found")
	if _, err := Prepare(context.Background(), config, ops, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("Prepare succeeded without sudo")
	}
}

func TestApplyRootAndNonRoot(t *testing.T) {
	for _, euid := range []int{0, 1000} {
		t.Run(map[bool]string{true: "root", false: "nonroot"}[euid == 0], func(t *testing.T) {
			config := validConfig(euid)
			ops := newFakeOps()
			plan, err := Prepare(context.Background(), config, ops, &bytes.Buffer{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := plan.Apply(context.Background(), ops, &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ops.createdDirs, []string{config.WorkflowsDir}) {
				t.Fatalf("created directories = %v", ops.createdDirs)
			}
			if euid == 0 {
				if string(ops.written[config.UnitPath]) != string(plan.Unit) {
					t.Fatal("root did not write the unit")
				}
				if !reflect.DeepEqual(ops.runs, []string{"/usr/bin/systemctl daemon-reload", "/usr/bin/systemctl enable deplite-agent", "/usr/bin/systemctl restart deplite-agent"}) {
					t.Fatalf("root commands = %v", ops.runs)
				}
			} else {
				want := []string{
					"/usr/bin/sudo -v",
					"/usr/bin/sudo install -m 0644 /tmp/deplite-agent.service.temp " + config.UnitPath,
					"/usr/bin/sudo systemctl daemon-reload",
					"/usr/bin/sudo systemctl enable deplite-agent",
					"/usr/bin/sudo systemctl restart deplite-agent",
				}
				if !reflect.DeepEqual(ops.runs, want) {
					t.Fatalf("nonroot commands = %v, want %v", ops.runs, want)
				}
				if !bytes.Equal(ops.tempData, plan.Unit) {
					t.Fatal("nonroot temp unit contents differ")
				}
			}
		})
	}
}

func TestPrepareUninstallOrder(t *testing.T) {
	config := validConfig(0)
	ops := newFakeOps()
	ops.files[config.UnitPath] = []byte("unit")
	plan, err := PrepareUninstall(context.Background(), "linux", config.UnitPath, 0, ops)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Exists {
		t.Fatal("expected installed service")
	}
	if err := plan.Apply(context.Background(), ops); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"run:/usr/bin/systemctl disable --now deplite-agent",
		"remove:" + config.UnitPath,
		"run:/usr/bin/systemctl daemon-reload",
	}
	if !reflect.DeepEqual(ops.events, want) {
		t.Fatalf("events = %v, want %v", ops.events, want)
	}
}

func TestInspectAndDataDirHint(t *testing.T) {
	config := validConfig(0)
	ops := newFakeOps()
	ops.files[config.UnitPath] = []byte("[Service]\nUser=alice\nEnvironment=DEPLITE_DATA_DIR=/service/data\nEnvironment=DEPLITE_WORKFLOWS_DIR=/service/workflows\nExecStart=/usr/bin/deplite-agent start\n")
	ops.runOutput["/usr/bin/systemctl is-active deplite-agent"] = []byte("active\n")
	info, err := Inspect(context.Background(), "linux", config.UnitPath, ops)
	if err != nil {
		t.Fatal(err)
	}
	if info == nil || !info.Active || info.User != "alice" || info.DataDir != "/service/data" || info.WorkflowsDir != "/service/workflows" {
		t.Fatalf("unexpected service info: %+v", info)
	}
	if hint := DataDirHint(info, "/cli/data"); !strings.Contains(hint, "/service/data") {
		t.Fatalf("missing mismatch hint: %q", hint)
	}
	if hint := DataDirHint(info, "/service/data"); hint != "" {
		t.Fatalf("unexpected same-dir hint: %q", hint)
	}
}

func TestUninstallDataDirHint(t *testing.T) {
	info := &Info{DataDir: "/service/data"}
	tests := []struct {
		name, current, flag, env string
		wantHint                 bool
	}{
		{name: "implicit mismatch", current: "/cli/data", wantHint: true},
		{name: "explicit flag", current: "/cli/data", flag: "/cli/data"},
		{name: "explicit environment", current: "/cli/data", env: "/cli/data"},
		{name: "same directory", current: "/service/data"},
		{name: "no service", current: "/cli/data"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := info
			if tc.name == "no service" {
				service = nil
			}
			hint := UninstallDataDirHint(service, tc.current, tc.flag, tc.env)
			if (hint != "") != tc.wantHint {
				t.Fatalf("hint = %q, want present=%t", hint, tc.wantHint)
			}
		})
	}
}
