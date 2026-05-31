package tui

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUUIDCell(t *testing.T) {
	assert.Contains(t, uuidCell("u1"), "u1")
}

func TestStateCell(t *testing.T) {
	assert.Contains(t, stateCell("started"), "● started")
	assert.Equal(t, "", stateCell(""))
}

func TestTUITableStylesSelectedHasBackground(t *testing.T) {
	s := tuiTableStyles()
	assert.NotEmpty(t, s.Selected.GetBackground(), "selected row has a background")
}

func TestHeaderRule(t *testing.T) {
	rule := headerRule([]table.Column{{Title: "A", Width: 3}, {Title: "B", Width: 2}})
	assert.Contains(t, rule, "───") // 3-wide column
	assert.Contains(t, rule, "──")  // 2-wide column
}

func TestWithHeaderRule(t *testing.T) {
	view := "HEADER LINE\nrow one\nrow two"
	out := withHeaderRule(view, []table.Column{{Title: "H", Width: 5}})
	lines := strings.Split(out, "\n")
	require.GreaterOrEqual(t, len(lines), 4)
	assert.Equal(t, "HEADER LINE", lines[0])
	assert.Contains(t, lines[1], "─", "rule spliced under the header")
	assert.Equal(t, "row one", lines[2])
}

func TestWithHeaderRule_NoRows(t *testing.T) {
	assert.Equal(t, "HEADER ONLY", withHeaderRule("HEADER ONLY", []table.Column{{Title: "H", Width: 5}}))
}
