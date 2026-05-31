package tui

import (
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerRows(t *testing.T) {
	servers := []upcloud.Server{
		{UUID: "u1", Hostname: "web-sg-1", Plan: "1xCPU-2GB", Zone: "sg-sin1", State: "started"},
		{UUID: "u2", Hostname: "db-sg-1", Plan: "2xCPU-4GB", Zone: "sg-sin1", State: "stopped"},
	}
	rows := serverRows(servers, nil, false)
	require.Len(t, rows, 2)
	assert.Equal(t, "web-sg-1", rows[0][0])
	assert.Equal(t, "started", rows[0][3])
	assert.Equal(t, "db-sg-1", rows[1][0])
	assert.Len(t, rows[0], 4, "no IP column when showIP is false")
}

func TestServerRows_WithIPColumn(t *testing.T) {
	servers := []upcloud.Server{
		{UUID: "u1", Hostname: "web-sg-1", State: "started"},
		{UUID: "u2", Hostname: "db-sg-1", State: "started"},
	}
	ipByUUID := map[string]string{"u1": "94.237.0.1"}
	rows := serverRows(servers, ipByUUID, true)
	require.Len(t, rows[0], 5)
	assert.Equal(t, "94.237.0.1", rows[0][4])
	assert.Equal(t, "—", rows[1][4], "unknown IP renders as em dash")
}

func TestServerColumns_IPToggle(t *testing.T) {
	assert.Len(t, serverColumns(false), 4)
	cols := serverColumns(true)
	require.Len(t, cols, 5)
	assert.Equal(t, "PUBLIC IP", cols[4].Title)
}

func TestPublicIPv4ByServer(t *testing.T) {
	ips := []upcloud.IPAddress{
		{Access: "public", Family: "IPv4", Address: "94.237.0.1", ServerUUID: "u1"},
		{Access: "public", Family: "IPv6", Address: "2a04::1", ServerUUID: "u1"},   // ignored
		{Access: "utility", Family: "IPv4", Address: "10.0.0.5", ServerUUID: "u1"}, // ignored
		{Access: "public", Family: "IPv4", Address: "209.50.0.2", ServerUUID: "u2"},
	}
	m := publicIPv4ByServer(ips)
	assert.Equal(t, "94.237.0.1", m["u1"])
	assert.Equal(t, "209.50.0.2", m["u2"])
	assert.Len(t, m, 2)
}
