package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFake() *cloud.Fake {
	return &cloud.Fake{
		Storages: []upcloud.Storage{{UUID: "s1", Title: "disk-a", Size: 25, Zone: "sg-sin1", State: "online", Tier: "maxiops"}},
		StorageDetails: map[string]*upcloud.StorageDetails{
			"s1": {Storage: upcloud.Storage{UUID: "s1", Title: "disk-a", Size: 25, State: "online"}},
		},
	}
}

func TestListCommand(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "disk-a")
}

func TestShowCommand(t *testing.T) {
	cmd := NewShowCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"disk-a"}) // by title
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "disk-a")
	assert.Contains(t, out.String(), "online")
}
