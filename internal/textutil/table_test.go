package textutil

import (
	"strings"
	"testing"
)

func TestDisplayWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"이름", 4},
		{"작업 ID", 7},
		{"토큰 3.0/3", 10},
	}
	for _, c := range cases {
		if got := DisplayWidth(c.in); got != c.want {
			t.Errorf("DisplayWidth(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// A Hangul header is one rune per two columns, so alignment has to be
// measured in columns or every later column drifts left.
func TestTableAlignsWideCells(t *testing.T) {
	var tbl Table
	tbl.Add("이름", "버전")
	tbl.Add("hello", "0.1.0")

	var b strings.Builder
	tbl.Render(&b)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	first := DisplayWidth(lines[0][:strings.Index(lines[0], "버전")])
	second := DisplayWidth(lines[1][:strings.Index(lines[1], "0.1.0")])
	if first != second {
		t.Errorf("second column starts at %d and %d; want the same column", first, second)
	}
}

func TestTableRenderIndent(t *testing.T) {
	var tbl Table
	tbl.Add("a", "b")
	var b strings.Builder
	tbl.RenderIndent(&b, "  ")
	if got := b.String(); !strings.HasPrefix(got, "  a") {
		t.Errorf("got %q, want it to start with the indent", got)
	}
}
