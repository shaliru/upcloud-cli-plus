package tui

import (
	"strings"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageRows(t *testing.T) {
	rows := storageRows([]upcloud.Storage{
		{UUID: "s1", Title: "disk-a", Size: 25, Zone: "sg-sin1", Tier: "maxiops", State: "online"},
	})
	require.Len(t, rows, 1)
	assert.Equal(t, "disk-a", rows[0][0])
}

func TestRenderStorageDetail(t *testing.T) {
	d := &upcloud.StorageDetails{
		Storage:     upcloud.Storage{UUID: "s1", Title: "disk-a", Size: 25, Zone: "sg-sin1", State: "online", Tier: "maxiops"},
		ServerUUIDs: upcloud.ServerUUIDSlice{"srv-1"},
	}
	out := renderStorageDetail(d, 60)
	assert.Contains(t, out, "disk-a")
	assert.Contains(t, out, "srv-1")
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, lipglossWidth(line), 60)
	}
}

func TestRenderStorageDetail_Nil(t *testing.T) {
	assert.Equal(t, "", renderStorageDetail(nil, 60))
}

func TestStoragePane_SelectedUUID(t *testing.T) {
	p := newStoragePane()
	p.setItems([]upcloud.Storage{{UUID: "s1", Title: "disk-a"}})
	uuid, ok := p.selectedUUID()
	require.True(t, ok)
	assert.Equal(t, "s1", uuid)
}
