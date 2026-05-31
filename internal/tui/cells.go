package tui

import (
	"charm.land/bubbles/v2/table"
	lipgloss "charm.land/lipgloss/v2"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

// uuidCell renders a UUID in the identifier colour.
func uuidCell(uuid string) string {
	return lipgloss.NewStyle().Foreground(styles.ColorBlue).Render(uuid)
}

// stateCell renders "● <state>" coloured by the state; "" stays "".
func stateCell(state string) string {
	if state == "" {
		return ""
	}
	return lipgloss.NewStyle().Foreground(styles.StateColor(state)).Render("● " + state)
}

// tuiTableStyles is the shared list-table styling: the selected row is a
// background highlight bar so per-cell colours show through.
func tuiTableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Selected = lipgloss.NewStyle().Background(styles.ColorSelection).Bold(true)
	return s
}

// defaultTableStyles returns the unmodified default table styles for comparison.
func defaultTableStyles() table.Styles {
	return table.DefaultStyles()
}
