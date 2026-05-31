package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, []Column{{Header: "NAME"}}, nil, "thing"))
	assert.Equal(t, "No thing found.\n", buf.String())
}

func TestWriteTable_BasicLayoutAndFooter(t *testing.T) {
	var buf bytes.Buffer
	cols := []Column{{Header: "NAME"}, {Header: "SIZE", Align: AlignRight}}
	rows := [][]string{{"disk-a", "25"}, {"b", "100"}}
	require.NoError(t, WriteTable(&buf, cols, rows, "disk"))
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 5) // header, sep, 2 rows, footer
	assert.Contains(t, lines[0], "NAME")
	assert.Contains(t, lines[1], "─", "separator rule")
	assert.Equal(t, strings.LastIndex(lines[2], "25")+len("25"), strings.LastIndex(lines[3], "100")+len("100"), "right-aligned ends align")
	assert.Equal(t, "2 disks", lines[len(lines)-1])
}

func TestWriteTable_Truncates(t *testing.T) {
	var buf bytes.Buffer
	cols := []Column{{Header: "NAME", MaxWidth: 5}}
	require.NoError(t, WriteTable(&buf, cols, [][]string{{"abcdefghij"}}, "thing"))
	assert.Contains(t, buf.String(), "abcd…")
	assert.NotContains(t, buf.String(), "abcde ")
}

func TestWriteTable_NoANSIWhenDisabled(t *testing.T) {
	EnableColor(false)
	var buf bytes.Buffer
	cols := []Column{{Header: "ID", ColorFn: func(s string) string { return colorize("#89b4fa", s) }}}
	require.NoError(t, WriteTable(&buf, cols, [][]string{{"u1"}}, "thing"))
	assert.NotContains(t, buf.String(), "\x1b[")
}

func TestWriteTable_Pluralisation(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, []Column{{Header: "X"}}, [][]string{{"a"}}, "server"))
	assert.Contains(t, buf.String(), "1 server\n")
	assert.NotContains(t, buf.String(), "1 servers")
}

func TestWriteTable_BrokenSeparator(t *testing.T) {
	var buf bytes.Buffer
	cols := []Column{{Header: "AAAA"}, {Header: "BB"}}
	rows := [][]string{{"aaaa", "bb"}}
	require.NoError(t, WriteTable(&buf, cols, rows, "row"))
	lines := strings.Split(buf.String(), "\n")
	sep := lines[1] // header, [separator], row, footer
	assert.Contains(t, sep, "────  ──", "per-column segments with a gap")
	assert.NotContains(t, sep, "──────", "no single unbroken run spanning columns")
}
