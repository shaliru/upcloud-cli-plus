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
		Storages: []upcloud.Storage{
			{UUID: "s1", Title: "disk-a", Size: 25, Zone: "sg-sin1", State: "online", Tier: "maxiops", Type: upcloud.StorageTypeNormal, Access: upcloud.StorageAccessPrivate},
			{UUID: "b1", Title: "backup-a", Type: upcloud.StorageTypeBackup, Access: upcloud.StorageAccessPrivate},
			{UUID: "t1", Title: "Ubuntu 24.04", Type: upcloud.StorageTypeTemplate, Access: upcloud.StorageAccessPublic},
		},
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

func TestListCommand_DefaultsToDevices(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "disk-a")
	assert.NotContains(t, out.String(), "Ubuntu 24.04", "public templates excluded by default")
	assert.NotContains(t, out.String(), "backup-a", "backups not in the devices default")
}

func TestListCommand_TypeBackups(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--type", "backups"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "backup-a")
	assert.NotContains(t, out.String(), "disk-a")
}

func TestListCommand_TypeAll(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--type", "all"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "Ubuntu 24.04", "all includes public templates")
}

func TestListCommand_TypeInvalid(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--type", "bogus"})
	assert.Error(t, cmd.Execute())
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
