package cloud

import (
	"context"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFakeImplementsService(t *testing.T) {
	var _ Service = (*Fake)(nil)
}

func TestFake_ListServers(t *testing.T) {
	f := &Fake{Servers: []upcloud.Server{{UUID: "u1", Hostname: "web"}}}

	servers, err := f.ListServers(context.Background())
	require.NoError(t, err)
	require.Len(t, servers, 1)
	assert.Equal(t, "web", servers[0].Hostname)
}

func TestFake_LifecycleRecordsCalls(t *testing.T) {
	f := &Fake{}
	require.NoError(t, f.StartServer(context.Background(), "u1"))
	require.NoError(t, f.StopServer(context.Background(), "u2"))
	require.NoError(t, f.RestartServer(context.Background(), "u3"))

	assert.Equal(t, []string{"u1"}, f.Started)
	assert.Equal(t, []string{"u2"}, f.Stopped)
	assert.Equal(t, []string{"u3"}, f.Restarted)
}

func TestFake_ListStorageAndNetworks(t *testing.T) {
	f := &Fake{
		Storages: []upcloud.Storage{{UUID: "s1", Title: "disk-a"}},
		Networks: []upcloud.Network{{UUID: "n1", Name: "net-a"}},
	}
	st, err := f.ListStorage(context.Background())
	require.NoError(t, err)
	require.Len(t, st, 1)
	assert.Equal(t, "disk-a", st[0].Title)

	nw, err := f.ListNetworks(context.Background())
	require.NoError(t, err)
	require.Len(t, nw, 1)
	assert.Equal(t, "net-a", nw[0].Name)
}
