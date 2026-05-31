package tui

import (
	"strings"

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

// headerRule is a broken separator aligned to the bubbles table's Padding(0,1)
// columns: one space (left pad) + dashes (column width) + one space (right pad)
// per column, so each dash run sits under its column with blank inter-column gaps.
func headerRule(cols []table.Column) string {
	var b strings.Builder
	for _, c := range cols {
		if c.Width <= 0 {
			continue
		}
		b.WriteString(" " + strings.Repeat("─", c.Width) + " ")
	}
	return styles.Muted.Render(b.String())
}

// withHeaderRule splices the broken rule between a table view's header line and
// its rows. A header-only view (no rows) is returned unchanged.
func withHeaderRule(tableView string, cols []table.Column) string {
	parts := strings.SplitN(tableView, "\n", 2)
	if len(parts) < 2 {
		return tableView
	}
	return parts[0] + "\n" + headerRule(cols) + "\n" + parts[1]
}
