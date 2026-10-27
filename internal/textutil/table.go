// Package textutil renders terminal tables aligned by display width.
package textutil

import (
	"fmt"
	"io"
	"strings"
)

// Table aligns columns by terminal display width. text/tabwriter counts
// runes, so a Hangul or CJK cell — two columns wide but one rune — pulls
// every later column out of line.
type Table struct {
	rows [][]string
}

// Add appends one row. Rows may differ in length; missing cells are
// treated as empty.
func (t *Table) Add(cells ...string) { t.rows = append(t.rows, cells) }

func (t *Table) Render(w io.Writer) { t.RenderIndent(w, "") }

// RenderIndent writes the table with each row prefixed by indent.
func (t *Table) RenderIndent(w io.Writer, indent string) {
	var widths []int
	for _, row := range t.rows {
		for i, cell := range row {
			for len(widths) <= i {
				widths = append(widths, 0)
			}
			if n := DisplayWidth(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, row := range t.rows {
		var b strings.Builder
		b.WriteString(indent)
		for i, cell := range row {
			if i == len(row)-1 {
				b.WriteString(cell)
				break
			}
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", widths[i]-DisplayWidth(cell)+2))
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

// wideRanges are the rune blocks a terminal renders two columns wide.
var wideRanges = [][2]rune{
	{0x1100, 0x115F},
	{0x2E80, 0x303E},
	{0x3041, 0x33FF},
	{0x3400, 0x4DBF},
	{0x4E00, 0x9FFF},
	{0xA000, 0xA4CF},
	{0xAC00, 0xD7A3},
	{0xF900, 0xFAFF},
	{0xFE30, 0xFE6F},
	{0xFF00, 0xFF60},
	{0xFFE0, 0xFFE6},
	{0x20000, 0x3FFFD},
}

// DisplayWidth counts the terminal columns s occupies.
func DisplayWidth(s string) int {
	n := 0
	for _, r := range s {
		n++
		for _, rg := range wideRanges {
			if r >= rg[0] && r <= rg[1] {
				n++
				break
			}
		}
	}
	return n
}
