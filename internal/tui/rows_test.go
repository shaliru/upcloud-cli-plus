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
	rows := serverRows(servers)
	require.Len(t, rows, 2)
	assert.Equal(t, "web-sg-1", rows[0][0])
	assert.Equal(t, "started", rows[0][3])
	assert.Equal(t, "db-sg-1", rows[1][0])
}
