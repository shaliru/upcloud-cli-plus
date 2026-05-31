package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

// renderServerDetail renders a server's details as a styled, width-bounded block:
// a header, an Overview key/value section, and Storage and Network sections.
// Long values are truncated to the width and columns are aligned (no tab stops).
// Returns "" for a nil server.
func renderServerDetail(d *upcloud.ServerDetails, width int) string {
	if d == nil {
		return ""
	}

	var b strings.Builder

	// Header: hostname (truncated to leave room for the state) + coloured state.
	state := lipgloss.NewStyle().Foreground(styles.StateColor(d.State)).Render("● " + d.State)
	hostBudget := width - lipgloss.Width(state) - 2
	host := styles.Title.Render(truncate(d.Hostname, hostBudget))
	b.WriteString(host + "  " + state + "\n")
	b.WriteString(styles.Muted.Render(truncate(fmt.Sprintf("%s · %s · %s", d.UUID, d.Plan, d.Zone), width)) + "\n\n")

	// Overview.
	b.WriteString(styles.Title.Render("Overview") + "\n")
	b.WriteString(kv("Title", d.Title, width))
	b.WriteString(kv("Group", d.ServerGroup, width))
	b.WriteString(kv("Timezone", d.Timezone, width))
	b.WriteString(kv("Firewall", d.Firewall, width))
	b.WriteString("\n")

	// Storage (aligned columns: title, size, address).
	b.WriteString(styles.Title.Render("Storage") + "\n")
	if len(d.StorageDevices) == 0 {
		b.WriteString(styles.Muted.Render("  (none)") + "\n")
	} else {
		rows := make([][]string, 0, len(d.StorageDevices))
		for _, sd := range d.StorageDevices {
			rows = append(rows, []string{sd.Title, fmt.Sprintf("%d GB", sd.Size), sd.Address})
		}
		b.WriteString(alignColumns(rows, width))
	}
	b.WriteString("\n")

	// Network (aligned columns: address, access, family).
	b.WriteString(styles.Title.Render("Network") + "\n")
	if len(d.IPAddresses) == 0 {
		b.WriteString(styles.Muted.Render("  (none)") + "\n")
	} else {
		rows := make([][]string, 0, len(d.IPAddresses))
		for _, ip := range d.IPAddresses {
			rows = append(rows, []string{ip.Address, ip.Access, ip.Family})
		}
		b.WriteString(alignColumns(rows, width))
	}

	return b.String()
}

// kv renders a padded key followed by a value truncated to the remaining width.
func kv(k, v string, width int) string {
	if v == "" {
		v = "—"
	}
	const keyWidth = 10 // "  " + key, padded
	key := styles.Key.Render(pad("  "+k, keyWidth))
	v = truncate(v, width-keyWidth-1)
	return key + " " + v + "\n"
}

// alignColumns renders rows as left-aligned columns padded to each column's
// widest cell, two spaces apart, each line indented and truncated to width.
func alignColumns(rows [][]string, width int) string {
	if len(rows) == 0 {
		return ""
	}
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if w := lipgloss.Width(r[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	var b strings.Builder
	for _, r := range rows {
		cells := make([]string, 0, cols)
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			if i == cols-1 { // don't pad the final column (no trailing space)
				cells = append(cells, cell)
			} else {
				cells = append(cells, pad(cell, widths[i]))
			}
		}
		line := "  " + strings.Join(cells, "  ")
		b.WriteString(truncate(line, width) + "\n")
	}
	return b.String()
}

// pad right-pads s with spaces to at least n display columns.
func pad(s string, n int) string {
	if d := n - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// truncate shortens s to at most max display columns, appending an ellipsis.
// Operates on the raw (unstyled) string, so call it before applying styles.
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}
