package network

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
		Networks: []upcloud.Network{
			{UUID: "n1", Name: "net-a", Type: upcloud.NetworkTypePrivate, Zone: "sg-sin1"},
			{UUID: "pub1", Name: "Public sg-sin1", Type: upcloud.NetworkTypePublic, Zone: "sg-sin1"},
		},
		NetworkDetails: map[string]*upcloud.Network{
			"n1": {UUID: "n1", Name: "net-a", Type: upcloud.NetworkTypePrivate, Zone: "sg-sin1"},
		},
	}
}

func TestListCommand(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "net-a")
}

func TestShowCommand(t *testing.T) {
	cmd := NewShowCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"net-a"}) // by name
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "net-a")
	assert.Contains(t, out.String(), "private")
}

func TestListCommand_DefaultsToPrivate(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "net-a")
	assert.NotContains(t, out.String(), "Public sg-sin1", "public/utility hidden by default")
}

func TestListCommand_TypeAll(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--type", "all"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "Public sg-sin1", "all includes infra")
}

func TestListCommand_TypeInvalid(t *testing.T) {
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return testFake(), nil })
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--type", "bogus"})
	assert.Error(t, cmd.Execute())
}
