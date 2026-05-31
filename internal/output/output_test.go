package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleServers() []upcloud.Server {
	return []upcloud.Server{
		{UUID: "u1", Hostname: "web-sg-1", Plan: "1xCPU-2GB", Zone: "sg-sin1", State: "started"},
		{UUID: "u2", Hostname: "db-sg-1", Plan: "2xCPU-4GB", Zone: "sg-sin1", State: "stopped"},
	}
}

func TestServersTable(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, ServersTable(&buf, sampleServers()))

	out := buf.String()
	assert.Contains(t, out, "HOSTNAME")
	assert.Contains(t, out, "web-sg-1")
	assert.Contains(t, out, "started")
	assert.Less(t, strings.Index(out, "HOSTNAME"), strings.Index(out, "web-sg-1"))
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sampleServers()))
	assert.Contains(t, buf.String(), `"hostname": "web-sg-1"`)
}

func TestYAML(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, YAML(&buf, sampleServers()))
	assert.Contains(t, buf.String(), "hostname: web-sg-1")
}

func TestStoragesTable(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, StoragesTable(&buf, []upcloud.Storage{
		{UUID: "s1", Title: "disk-a", Size: 25, Zone: "sg-sin1", State: "online", Type: "normal", Tier: "maxiops"},
	}))
	out := buf.String()
	assert.Contains(t, out, "TITLE")
	assert.Contains(t, out, "disk-a")
	assert.Contains(t, out, "25")
}

func TestNetworksTable(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NetworksTable(&buf, []upcloud.Network{
		{UUID: "n1", Name: "net-a", Type: "private", Zone: "sg-sin1"},
	}))
	out := buf.String()
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "net-a")
	assert.Contains(t, out, "private")
}
