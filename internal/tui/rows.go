package tui

import (
	"charm.land/bubbles/v2/table"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverColumns defines the list-pane columns. When showIP is true a PUBLIC IP
// column is appended (omitted on narrow terminals to save horizontal space).
func serverColumns(showIP bool) []table.Column {
	cols := []table.Column{
		{Title: "HOSTNAME", Width: 22},
		{Title: "PLAN", Width: 18},
		{Title: "ZONE", Width: 10},
		{Title: "STATE", Width: 10},
	}
	if showIP {
		cols = append(cols, table.Column{Title: "PUBLIC IP", Width: 16})
	}
	return cols
}

// serverRows converts servers into table rows. Column order matches
// serverColumns(showIP). ipByUUID maps a server UUID to its public IPv4 (may be
// empty); when showIP is true the column shows the IP or "—" if unknown.
func serverRows(servers []upcloud.Server, ipByUUID map[string]string, showIP bool) []table.Row {
	rows := make([]table.Row, 0, len(servers))
	for _, s := range servers {
		row := table.Row{s.Hostname, s.Plan, s.Zone, s.State}
		if showIP {
			ip := ipByUUID[s.UUID]
			if ip == "" {
				ip = "—"
			}
			row = append(row, ip)
		}
		rows = append(rows, row)
	}
	return rows
}

// publicIPv4ByServer builds a server-UUID → public IPv4 map from a flat IP list.
func publicIPv4ByServer(ips []upcloud.IPAddress) map[string]string {
	m := make(map[string]string)
	for _, ip := range ips {
		if ip.Access == "public" && ip.Family == "IPv4" && ip.ServerUUID != "" {
			m[ip.ServerUUID] = ip.Address
		}
	}
	return m
}
