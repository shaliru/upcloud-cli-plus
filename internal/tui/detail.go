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
// Returns "" for a nil server.
func renderServerDetail(d *upcloud.ServerDetails, width int) string {
	if d == nil {
		return ""
	}

	var b strings.Builder

	state := lipgloss.NewStyle().Foreground(styles.StateColor(d.State)).Render("● " + d.State)
	b.WriteString(styles.Title.Render(d.Hostname) + "  " + state + "\n")
	b.WriteString(styles.Muted.Render(fmt.Sprintf("%s · %s · %s", d.UUID, d.Plan, d.Zone)) + "\n\n")

	b.WriteString(styles.Title.Render("Overview") + "\n")
	b.WriteString(kv("Title", d.Title))
	b.WriteString(kv("Group", d.ServerGroup))
	b.WriteString(kv("Timezone", d.Timezone))
	b.WriteString(kv("Firewall", d.Firewall))
	b.WriteString("\n")

	b.WriteString(styles.Title.Render("Storage") + "\n")
	if len(d.StorageDevices) == 0 {
		b.WriteString(styles.Muted.Render("  (none)") + "\n")
	}
	for _, sd := range d.StorageDevices {
		b.WriteString(fmt.Sprintf("  %s\t%d GB\t%s\n", sd.Title, sd.Size, sd.Address))
	}
	b.WriteString("\n")

	b.WriteString(styles.Title.Render("Network") + "\n")
	if len(d.IPAddresses) == 0 {
		b.WriteString(styles.Muted.Render("  (none)") + "\n")
	}
	for _, ip := range d.IPAddresses {
		b.WriteString(fmt.Sprintf("  %s\t%s\t%s\n", ip.Address, ip.Access, ip.Family))
	}

	return lipgloss.NewStyle().Width(width).Render(b.String())
}

func kv(k, v string) string {
	if v == "" {
		v = "—"
	}
	return styles.Key.Render("  "+k+"  ") + v + "\n"
}
