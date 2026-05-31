package tui

import (
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverPane holds the list (left) and detail viewport (right) for servers.
type serverPane struct {
	list    table.Model
	detail  viewport.Model
	servers []upcloud.Server
}

func newServerPane() serverPane {
	t := table.New(
		table.WithColumns(serverColumns()),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	return serverPane{list: t, detail: viewport.New()}
}

func (p *serverPane) setServers(servers []upcloud.Server) {
	p.servers = servers
	p.list.SetRows(serverRows(servers))
}

// selectedUUID returns the UUID of the highlighted server, or "" if none.
func (p *serverPane) selectedUUID() string {
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(p.servers) {
		return ""
	}
	return p.servers[cur].UUID
}
