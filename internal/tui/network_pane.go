package tui

import (
	"strings"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

// networkPane is a read-only list + detail pane for networks. Detail renders
// directly from the loaded list item (GetNetworks already returns full objects).
type networkPane struct {
	list    table.Model
	detail  viewport.Model
	all     []upcloud.Network
	showAll bool
	loaded  bool
}

func networkColumns() []table.Column {
	return []table.Column{
		{Title: "UUID", Width: 36},
		{Title: "NAME", Width: 24},
		{Title: "TYPE", Width: 10},
		{Title: "ZONE", Width: 10},
	}
}

func networkRows(items []upcloud.Network) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, n := range items {
		rows = append(rows, table.Row{n.UUID, n.Name, n.Type, n.Zone})
	}
	return rows
}

func newNetworkPane() networkPane {
	t := table.New(table.WithColumns(networkColumns()), table.WithFocused(true), table.WithHeight(10))
	return networkPane{list: t, detail: viewport.New()}
}

func (p *networkPane) setItems(items []upcloud.Network) {
	p.all = items
	p.loaded = true
	p.refreshRows()
}

// visible returns the networks shown for the current mode.
func (p *networkPane) visible() []upcloud.Network {
	mode := "private"
	if p.showAll {
		mode = "all"
	}
	return cloud.FilterNetworksByType(p.all, mode)
}

func (p *networkPane) refreshRows() {
	p.list.SetRows(networkRows(p.visible()))
	if len(p.visible()) > 0 {
		p.list.SetCursor(0)
	}
}

func (p *networkPane) toggleAll() { p.showAll = !p.showAll; p.refreshRows() }

// indicator is the one-line mode label shown above the list.
func (p *networkPane) indicator() string {
	if p.showAll {
		return styles.Muted.Render("Showing: all networks (incl. UpCloud infra) · a: private")
	}
	return styles.Muted.Render("Showing: private networks · a: all")
}

func (p *networkPane) selectedItem() (upcloud.Network, bool) {
	items := p.visible()
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(items) {
		return upcloud.Network{}, false
	}
	return items[cur], true
}

func (p *networkPane) listView() string {
	if len(p.visible()) == 0 {
		return styles.Muted.Render("  (none)")
	}
	return p.list.View()
}

func (p *networkPane) detailView() string { return p.detail.View() }

// renderNetworkDetail renders network details (read-only), width-bounded.
func renderNetworkDetail(n *upcloud.Network, width int) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(styles.Title.Render(truncate(n.Name, width)) + "\n")
	b.WriteString(styles.Muted.Render(truncate(n.UUID, width)) + "\n\n")
	b.WriteString(styles.Title.Render("Overview") + "\n")
	b.WriteString(kv("Type", n.Type, width))
	b.WriteString(kv("Zone", n.Zone, width))
	b.WriteString(kv("Router", n.Router, width))
	b.WriteString("\n")
	b.WriteString(styles.Title.Render("IP networks") + "\n")
	if len(n.IPNetworks) == 0 {
		b.WriteString(styles.Muted.Render("  (none)") + "\n")
	} else {
		rows := make([][]string, 0, len(n.IPNetworks))
		for _, ipn := range n.IPNetworks {
			rows = append(rows, []string{ipn.Address, ipn.Family, "gw " + ipn.Gateway})
		}
		b.WriteString(alignColumns(rows, width))
	}
	return b.String()
}
