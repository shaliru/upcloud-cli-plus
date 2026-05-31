package tui

import (
	"strings"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkRows(t *testing.T) {
	rows := networkRows([]upcloud.Network{{UUID: "n1", Name: "net-a", Type: "private", Zone: "sg-sin1"}})
	require.Len(t, rows, 1)
	assert.Equal(t, "net-a", rows[0][0])
}

func TestRenderNetworkDetail(t *testing.T) {
	n := &upcloud.Network{
		UUID: "n1", Name: "net-a", Type: "private", Zone: "sg-sin1",
		IPNetworks: upcloud.IPNetworkSlice{{Address: "10.0.0.0/24", Family: "IPv4", Gateway: "10.0.0.1"}},
	}
	out := renderNetworkDetail(n, 60)
	assert.Contains(t, out, "net-a")
	assert.Contains(t, out, "10.0.0.0/24")
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, lipglossWidth(line), 60)
	}
}

func TestNetworkPane_SelectedItem(t *testing.T) {
	p := newNetworkPane()
	p.setItems([]upcloud.Network{{UUID: "n1", Name: "net-a"}})
	item, ok := p.selectedItem()
	require.True(t, ok)
	assert.Equal(t, "n1", item.UUID)
}
