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
		Networks: []upcloud.Network{{UUID: "n1", Name: "net-a", Type: "private", Zone: "sg-sin1"}},
		NetworkDetails: map[string]*upcloud.Network{
			"n1": {UUID: "n1", Name: "net-a", Type: "private", Zone: "sg-sin1"},
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
