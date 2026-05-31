package tui

import (
	"charm.land/bubbles/v2/table"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// serverColumns are the full-width server list columns (UUID-led, with PUBLIC IP).
func serverColumns() []table.Column {
	return []table.Column{
		{Title: "UUID", Width: 36},
		{Title: "HOSTNAME", Width: 22},
		{Title: "PLAN", Width: 18},
		{Title: "ZONE", Width: 10},
		{Title: "STATE", Width: 10},
		{Title: "PUBLIC IP", Width: 16},
	}
}

func serverRows(servers []upcloud.Server, ipByUUID map[string]string) []table.Row {
	rows := make([]table.Row, 0, len(servers))
	for _, s := range servers {
		ip := ipByUUID[s.UUID]
		if ip == "" {
			ip = "—"
		}
		rows = append(rows, table.Row{uuidCell(s.UUID), s.Hostname, s.Plan, s.Zone, stateCell(s.State), ip})
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
