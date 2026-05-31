package tui

import (
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverPane holds the list (left) and detail viewport (right) for servers.
type serverPane struct {
	list     table.Model
	detail   viewport.Model
	servers  []upcloud.Server
	ipByUUID map[string]string
	showIP   bool
}

func newServerPane() serverPane {
	t := table.New(
		table.WithColumns(serverColumns(false)),
		table.WithFocused(true),
		table.WithHeight(10),
	)
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

// setShowIP toggles the PUBLIC IP column, rebuilding columns and rows if changed.
func (p *serverPane) setShowIP(show bool) {
	if show == p.showIP {
		return
	}
	p.showIP = show
	p.list.SetColumns(serverColumns(show))
	p.rebuild()
}

// rebuild refreshes the table rows from the current servers, IP map and showIP.
func (p *serverPane) rebuild() {
	p.list.SetRows(serverRows(p.servers, p.ipByUUID, p.showIP))
}

// selectedUUID returns the UUID of the highlighted server, or "" if none.
func (p *serverPane) selectedUUID() string {
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(p.servers) {
		return ""
	}
	return p.servers[cur].UUID
}
