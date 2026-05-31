package tui

import (
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverPane holds the list and detail viewport for servers.
type serverPane struct {
	list     table.Model
	detail   viewport.Model
	servers  []upcloud.Server
	ipByUUID map[string]string
}

func newServerPane() serverPane {
	t := table.New(table.WithColumns(serverColumns()), table.WithFocused(true), table.WithHeight(10), table.WithStyles(tuiTableStyles()))
	return serverPane{list: t, detail: viewport.New()}
}

func (p *serverPane) setServers(servers []upcloud.Server) {
	p.servers = servers
	p.rebuild()
}

func (p *serverPane) setIPs(ipByUUID map[string]string) {
	p.ipByUUID = ipByUUID
	p.rebuild()
}

// rebuild refreshes the table rows from the current servers and IP map.
func (p *serverPane) rebuild() {
	p.list.SetRows(serverRows(p.servers, p.ipByUUID))
	if p.list.Cursor() < 0 && len(p.servers) > 0 {
		p.list.SetCursor(0)
	}
}

// selectedUUID returns the UUID of the highlighted server, or "" if none.
func (p *serverPane) selectedUUID() string {
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(p.servers) {
		return ""
	}
	return p.servers[cur].UUID
}

func (p *serverPane) listView() string   { return p.list.View() }
func (p *serverPane) detailView() string { return p.detail.View() }
