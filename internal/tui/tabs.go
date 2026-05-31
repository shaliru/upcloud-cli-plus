package tui

import (
	"strings"

	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

// renderTabs renders a single-line tab bar; the active tab is highlighted.
func renderTabs(active int, names []string) string {
	parts := make([]string, len(names))
	for i, name := range names {
		if i == active {
			parts[i] = styles.Title.Render(name)
		} else {
			parts[i] = styles.Muted.Render(name)
		}
	}
	return strings.Join(parts, styles.Muted.Render("  │  "))
}
