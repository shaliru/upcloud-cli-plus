package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Align controls horizontal cell alignment.
type Align int

const (
	AlignLeft Align = iota
	AlignRight
)

// Column describes one table column.
type Column struct {
	Header   string
	Align    Align
	MaxWidth int                      // 0 = no cap; else ellipsis-truncate cells to this display width
	ColorFn  func(cell string) string // optional colour for cells (not the header); nil = none
}

// WriteTable renders cols+rows as an aligned table with a bold header, a dim
// separator rule, two-space column gaps, and a dim "<n> <noun>(s)" footer.
// Empty rows yield "No <noun> found.". Colour is applied only when enabled
// (see EnableColor); widths are computed from plain, truncated cell text.
func WriteTable(w io.Writer, cols []Column, rows [][]string, noun string) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintf(w, "No %s found.\n", noun)
		return err
	}

	plain := make([][]string, len(rows))
	for r, row := range rows {
		plain[r] = make([]string, len(cols))
		for c := range cols {
			cell := ""
			if c < len(row) {
				cell = row[c]
			}
			if cols[c].MaxWidth > 0 {
				cell = truncateCell(cell, cols[c].MaxWidth)
			}
			plain[r][c] = cell
		}
	}

	widths := make([]int, len(cols))
	for c := range cols {
		widths[c] = dispWidth(cols[c].Header)
		for r := range plain {
			if wd := dispWidth(plain[r][c]); wd > widths[c] {
				widths[c] = wd
			}
		}
	}

	var b strings.Builder

	headerCells := make([]string, len(cols))
	for c := range cols {
		headerCells[c] = bold(padCell(cols[c].Header, widths[c], cols[c].Align))
	}
	b.WriteString(strings.Join(headerCells, "  ") + "\n")

	total := 0
	for _, wd := range widths {
		total += wd
	}
	total += 2 * (len(cols) - 1)
	b.WriteString(dim(strings.Repeat("─", total)) + "\n")

	for r := range plain {
		cells := make([]string, len(cols))
		for c := range cols {
			val := plain[r][c]
			if val == "" {
				val = "—"
			}
			padded := padCell(val, widths[c], cols[c].Align)
			switch {
			case val == "—":
				padded = applyColorPreservingPad(padded, val, dim)
			case cols[c].ColorFn != nil:
				padded = applyColorPreservingPad(padded, val, cols[c].ColorFn)
			}
			cells[c] = padded
		}
		b.WriteString(strings.Join(cells, "  ") + "\n")
	}

	b.WriteString(dim(fmt.Sprintf("%d %s", len(rows), pluralise(noun, len(rows)))) + "\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// applyColorPreservingPad colours the value portion of an already-padded cell,
// leaving the padding spaces uncoloured so alignment is unaffected.
func applyColorPreservingPad(padded, value string, fn func(string) string) string {
	idx := strings.Index(padded, value)
	if idx < 0 || value == "" {
		return padded
	}
	return padded[:idx] + fn(value) + padded[idx+len(value):]
}

func padCell(s string, width int, align Align) string {
	gap := width - dispWidth(s)
	if gap <= 0 {
		return s
	}
	pad := strings.Repeat(" ", gap)
	if align == AlignRight {
		return pad + s
	}
	return s + pad
}

func truncateCell(s string, max int) string {
	if max <= 0 || dispWidth(s) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}

func dispWidth(s string) int { return utf8.RuneCountInString(s) }

func pluralise(noun string, n int) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}
