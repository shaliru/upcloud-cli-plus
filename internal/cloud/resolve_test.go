package cloud

import (
	"context"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newResolveFake() *Fake {
	return &Fake{Servers: []upcloud.Server{
		{UUID: "00000000-0000-0000-0000-000000000001", Hostname: "web-sg-1", Title: "web"},
		{UUID: "00000000-0000-0000-0000-000000000002", Hostname: "db-sg-1", Title: "db"},
		{UUID: "00000000-0000-0000-0000-000000000003", Hostname: "dup", Title: "dup"},
		{UUID: "00000000-0000-0000-0000-000000000004", Hostname: "dup", Title: "other"},
	}}
}

func TestResolveServer_ByUUID(t *testing.T) {
	uuid, err := ResolveServer(context.Background(), newResolveFake(), "00000000-0000-0000-0000-000000000001")
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", uuid)
}

func TestResolveServer_ByHostname(t *testing.T) {
	uuid, err := ResolveServer(context.Background(), newResolveFake(), "db-sg-1")
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", uuid)
}

func TestResolveServer_NotFound(t *testing.T) {
	_, err := ResolveServer(context.Background(), newResolveFake(), "nope")
	assert.ErrorContains(t, err, "no server")
}

func TestResolveServer_Ambiguous(t *testing.T) {
	_, err := ResolveServer(context.Background(), newResolveFake(), "dup")
	assert.ErrorContains(t, err, "ambiguous")
}
