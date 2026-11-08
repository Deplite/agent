package workflow

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseLoadPathAndValidName(t *testing.T) {
	body := []byte("name: hello\nsteps:\n  - name: greet\n    run: echo hi\n")
	wf, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Path != "" {
		t.Fatalf("Parse path = %q, want empty", wf.Path)
	}
	path := filepath.Join(t.TempDir(), "nested", "workflow.yml")
	if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	wf, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Path != path {
		t.Fatalf("LoadFile path = %q, want %q", wf.Path, path)
	}
	for _, name := range []string{"a", "A_1", "a.b-c", strings.Repeat("x", 128)} {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false", name)
		}
	}
	for _, name := range []string{"", strings.Repeat("x", 129), "a b", "한글"} {
		if ValidName(name) {
			t.Errorf("ValidName(%q) = true", name)
		}
	}
}

func TestSetNamePreservesSourceFormatting(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "# heading\n\nname: old # keep\nsteps:\n  - name: hello\n    run: echo hi\n", "# heading\n\nname: next # keep\nsteps:\n  - name: hello\n    run: echo hi\n"},
		{"double quoted", "name: \"old\" # keep\nsteps: [{name: hello, run: echo hi}]\n", "name: \"next\" # keep\nsteps: [{name: hello, run: echo hi}]\n"},
		{"single quoted", "name: 'old' # keep\nsteps: [{name: hello, run: echo hi}]\n", "name: 'next' # keep\nsteps: [{name: hello, run: echo hi}]\n"},
		{"BOM", "\uFEFFname: old\nsteps: [{name: hello, run: echo hi}]\n", "\uFEFFname: next\nsteps: [{name: hello, run: echo hi}]\n"},
		{"CRLF", "# heading\r\n\r\nname: old\r\nsteps:\r\n  - name: hello\r\n    run: echo hi\r\n", "# heading\r\n\r\nname: next\r\nsteps:\r\n  - name: hello\r\n    run: echo hi\r\n"},
		{"flow mapping", "{name: old, steps: [{name: hello, run: echo hi}]}\n", "{name: next, steps: [{name: hello, run: echo hi}]}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SetName([]byte(test.in), "next")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("SetName() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSetNameAcceptsPlainNonStringSourceTag(t *testing.T) {
	body := []byte("name: 123\nsteps: [{name: hello, run: echo hi}]\n")
	got, err := SetName(body, "next")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("name: next\nsteps: [{name: hello, run: echo hi}]\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SetName() = %q, want %q", got, want)
	}
}

func TestSetNameQuotesNewPlainScalars(t *testing.T) {
	for _, name := range []string{"123", "1e3", "true", "null", "yes", "OFF", "~", "...", "---", "-"} {
		body, err := SetName([]byte("name: old\nsteps: [{name: hello, run: echo hi}]\n"), name)
		if err != nil {
			t.Fatalf("SetName(%q): %v", name, err)
		}
		if !strings.Contains(string(body), "name: \""+name+"\"") {
			t.Errorf("SetName(%q) did not quote the new scalar: %q", name, body)
		}
		var doc struct {
			Name any `yaml:"name"`
		}
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Name != name {
			t.Errorf("name decoded as %#v, want string %q", doc.Name, name)
		}
	}
}

func TestSetNameRejectsUnsupportedTokens(t *testing.T) {
	for _, body := range []string{
		"name: |\n  old\nsteps: [{name: hello, run: echo hi}]\n",
		"name: >\n  old\nsteps: [{name: hello, run: echo hi}]\n",
		"steps: [{name: hello, run: echo hi}]\n",
	} {
		if _, err := SetName([]byte(body), "next"); err == nil {
			t.Errorf("SetName accepted %q", body)
		}
	}
}

func TestDuplicateNames(t *testing.T) {
	got := DuplicateNames([]Workflow{
		{Name: "same", Path: "z.yml"},
		{Name: "other", Path: "other.yml"},
		{Name: "same", Path: "a.yml"},
	})
	want := map[string][]string{"same": {"a.yml", "z.yml"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DuplicateNames() = %#v, want %#v", got, want)
	}
}
