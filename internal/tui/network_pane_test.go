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
	assert.Contains(t, rows[0][0], "n1", "UUID is first column")
	assert.Equal(t, "net-a", rows[0][1])
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
	p.setItems([]upcloud.Network{{UUID: "n1", Name: "net-a", Type: upcloud.NetworkTypePrivate}})
	item, ok := p.selectedItem()
	require.True(t, ok)
	assert.Equal(t, "n1", item.UUID)
}

func mixedFakeNetworks() []upcloud.Network {
	return []upcloud.Network{
		{UUID: "n1", Name: "net-a", Type: upcloud.NetworkTypePrivate, Zone: "sg-sin1"},
		{UUID: "pub1", Name: "Public sg-sin1", Type: upcloud.NetworkTypePublic, Zone: "sg-sin1"},
	}
}

func TestNetworkPane_DefaultsToPrivateAndToggles(t *testing.T) {
	p := newNetworkPane()
	p.setItems(mixedFakeNetworks())

	item, ok := p.selectedItem()
	require.True(t, ok)
	assert.Equal(t, "n1", item.UUID)
	assert.Len(t, p.visible(), 1)

	p.toggleAll()
	assert.Len(t, p.visible(), 2)

	p.toggleAll()
	assert.Len(t, p.visible(), 1)
}

func TestNetworkPane_IndicatorMentionsMode(t *testing.T) {
	p := newNetworkPane()
	assert.Contains(t, p.indicator(), "private")
	p.toggleAll()
	assert.Contains(t, p.indicator(), "all")
}

func TestNetworkPane_ListViewAndDetailView(t *testing.T) {
	p := newNetworkPane()
	p.setItems(mixedFakeNetworks())
	assert.NotEmpty(t, p.listView())
	assert.NotPanics(t, func() { _ = p.detailView() })
}
