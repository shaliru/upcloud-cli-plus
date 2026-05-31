package tui

import (
	"charm.land/bubbles/v2/table"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverColumns defines the list-pane columns.
func serverColumns() []table.Column {
	return []table.Column{
		{Title: "HOSTNAME", Width: 22},
		{Title: "PLAN", Width: 18},
		{Title: "ZONE", Width: 10},
		{Title: "STATE", Width: 10},
	}
}

// serverRows converts servers into table rows. Column order matches serverColumns.
func serverRows(servers []upcloud.Server) []table.Row {
	rows := make([]table.Row, 0, len(servers))
	for _, s := range servers {
		rows = append(rows, table.Row{s.Hostname, s.Plan, s.Zone, s.State})
	}
	return rows
}
