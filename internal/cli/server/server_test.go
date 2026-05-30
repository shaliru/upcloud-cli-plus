package server

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
	return &cloud.Fake{Servers: []upcloud.Server{
		{UUID: "u1", Hostname: "web-sg-1", Plan: "1xCPU-2GB", Zone: "sg-sin1", State: "started"},
	}}
}

func TestListCommand_Table(t *testing.T) {
	f := testFake()
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return f, nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "web-sg-1")
}

func TestListCommand_JSON(t *testing.T) {
	f := testFake()
	cmd := NewListCommand(func(context.Context) (cloud.Service, error) { return f, nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"-o", "json"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"hostname": "web-sg-1"`)
}

func TestShowCommand(t *testing.T) {
	f := testFake()
	f.Details = map[string]*upcloud.ServerDetails{
		"u1": {Server: upcloud.Server{UUID: "u1", Hostname: "web-sg-1", State: "started"}},
	}
	cmd := NewShowCommand(func(context.Context) (cloud.Service, error) { return f, nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"web-sg-1"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "web-sg-1")
	assert.Contains(t, out.String(), "started")
}

func TestLifecycleCommand_Restart(t *testing.T) {
	f := testFake()
	cmd := NewLifecycleCommand(func(context.Context) (cloud.Service, error) { return f, nil }, "restart")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"web-sg-1"})

	require.NoError(t, cmd.Execute())
	assert.Equal(t, []string{"u1"}, f.Restarted)
}

func TestLifecycleCommand_ReportsFailures(t *testing.T) {
	f := testFake()
	cmd := NewLifecycleCommand(func(context.Context) (cloud.Service, error) { return f, nil }, "start")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"nonexistent"})

	err := cmd.Execute()
	require.Error(t, err)
	var fc FailureCountError
	require.ErrorAs(t, err, &fc)
	assert.Equal(t, 1, fc.Count)
}
