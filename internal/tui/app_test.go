package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApp_QuitOnQ(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	_, cmd := app.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	assert.NotNil(t, cmd)
	msg := cmd()
	_, isQuit := msg.(tea.QuitMsg)
	assert.True(t, isQuit, "pressing q should issue tea.Quit")
}

func TestApp_PublicIPColumnPopulates(t *testing.T) {
	f := &cloud.Fake{Servers: []upcloud.Server{{UUID: "u1", Hostname: "web-sg-1", State: "started"}}}
	app := NewWithService(f)
	app.width, app.height = 200, 30 // wide enough → PUBLIC IP column shown
	app.resize()
	_, _ = app.Update(serversLoadedMsg{servers: f.Servers})
	_, _ = app.Update(ipsLoadedMsg{ips: []upcloud.IPAddress{
		{Access: "public", Family: "IPv4", Address: "94.237.73.201", ServerUUID: "u1"},
	}})
	assert.Contains(t, app.viewString(), "94.237.73.201")
}

func TestApp_NarrowHidesIPColumn(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 80, 30 // total < 118 → no IP column
	app.resize()
	assert.False(t, app.pane.showIP)
}

func TestApp_ErrorShownFullyAndWrapped(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 120, 30
	app.resize()
	longErr := errorString("The operation is not allowed while the server 00187417-b22d-4850-99f0-6b0bebb8d911 is in state 'started'. (type=SERVER_STATE_ILLEGAL, status=409)")
	_, _ = app.Update(errMsg{err: longErr})

	out := app.viewString()
	// No line overflows the width...
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, lipglossWidth(line), 120, "line exceeds width: %q", line)
	}
	// ...yet the FULL error is present, including the tail that used to be cut.
	flat := strings.ReplaceAll(out, "\n", " ")
	assert.Contains(t, flat, "not allowed")
	assert.Contains(t, flat, "status=409", "the end of the error must not be truncated")
	// The error wrapped onto more than one line.
	assert.Greater(t, strings.Count(app.errorBlock(), "\n"), 0, "long error should wrap")
}

func TestApp_ErrorClearedOnKeypress(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 120, 30
	app.resize()
	_, _ = app.Update(errMsg{err: errorString("boom happened")})
	require.Contains(t, app.viewString(), "boom happened")

	_, _ = app.Update(tea.KeyPressMsg{Code: 'j', Text: "j"}) // any key acknowledges
	assert.NotContains(t, app.viewString(), "boom happened")
}

func TestApp_ServersLoadedPopulatesTable(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 100, 30
	servers := []upcloud.Server{{UUID: "u1", Hostname: "web-sg-1", State: "started"}}
	_, _ = app.Update(serversLoadedMsg{servers: servers})
	assert.Contains(t, app.viewString(), "web-sg-1")
}

func TestApp_ErrShownInStatus(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 100, 30
	_, _ = app.Update(errMsg{err: errorString("boom")})
	assert.Contains(t, app.viewString(), "boom")
}

func TestApp_RestartActionCallsService(t *testing.T) {
	f := &cloud.Fake{Servers: []upcloud.Server{{UUID: "u1", Hostname: "web-sg-1", State: "started"}}}
	app := NewWithService(f)
	app.width, app.height = 100, 30
	_, _ = app.Update(serversLoadedMsg{servers: f.Servers})

	_, _ = app.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	assert.Contains(t, app.viewString(), "confirm")

	_, cmd := app.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	require.NotNil(t, cmd)
	msg := cmd()
	_, ok := msg.(actionDoneMsg)
	assert.True(t, ok)
	assert.Equal(t, []string{"u1"}, f.Restarted)
}

func TestApp_TabCyclesActive(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 160, 30
	app.resize()
	require.Equal(t, 0, app.active)
	_, _ = app.Update(tea.KeyPressMsg{Code: '\t', Text: "tab"})
	assert.Equal(t, 1, app.active)
	_, _ = app.Update(tea.KeyPressMsg{Code: '\t', Text: "tab"})
	assert.Equal(t, 2, app.active)
	_, _ = app.Update(tea.KeyPressMsg{Code: '\t', Text: "tab"})
	assert.Equal(t, 0, app.active, "wraps around")
}

func TestApp_StartTabFromResource(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.setStartTab("storage")
	assert.Equal(t, 1, app.active)
	app.setStartTab("network")
	assert.Equal(t, 2, app.active)
	app.setStartTab("server")
	assert.Equal(t, 0, app.active)
	app.setStartTab("")
	assert.Equal(t, 0, app.active)
}

func TestApp_TabClearsPendingConfirm(t *testing.T) {
	f := &cloud.Fake{Servers: []upcloud.Server{{UUID: "u1", Hostname: "web-sg-1", State: "started"}}}
	app := NewWithService(f)
	app.width, app.height = 160, 30
	app.resize()
	_, _ = app.Update(serversLoadedMsg{servers: f.Servers})

	_, _ = app.Update(tea.KeyPressMsg{Code: 'r', Text: "r"}) // arm a confirm
	require.NotEmpty(t, app.pending)
	_, _ = app.Update(tea.KeyPressMsg{Code: '\t', Text: "tab"})
	assert.Empty(t, app.pending, "switching tabs clears the pending confirm")
	assert.Empty(t, app.status, "switching tabs clears the confirm prompt")
}

func TestApp_StorageTabShowsLoadedStorage(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 160, 30
	app.resize()
	_, _ = app.Update(storageLoadedMsg{items: []upcloud.Storage{{UUID: "s1", Title: "disk-a", Type: upcloud.StorageTypeNormal}}})
	app.active = 1
	assert.Contains(t, app.viewString(), "disk-a")
}

func TestApp_NetworkTabShowsLoadedNetworks(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 160, 30
	app.resize()
	_, _ = app.Update(networksLoadedMsg{items: []upcloud.Network{{UUID: "n1", Name: "net-a", Type: upcloud.NetworkTypePrivate}}})
	app.active = 2
	assert.Contains(t, app.viewString(), "net-a")
}

func TestApp_StorageSubCategorySwitch(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	app.width, app.height = 160, 30
	app.resize()
	app.active = 1 // storage tab
	_, _ = app.Update(storageLoadedMsg{items: []upcloud.Storage{
		{UUID: "d1", Title: "disk-a", Type: upcloud.StorageTypeNormal, Access: upcloud.StorageAccessPrivate},
		{UUID: "b1", Title: "backup-a", Type: upcloud.StorageTypeBackup, Access: upcloud.StorageAccessPrivate},
	}})
	out := app.viewString()
	assert.Contains(t, out, "Devices")
	assert.Contains(t, out, "disk-a")
	assert.NotContains(t, out, "backup-a")

	_, _ = app.Update(tea.KeyPressMsg{Code: ']', Text: "]"})
	out = app.viewString()
	assert.Contains(t, out, "backup-a")
	assert.NotContains(t, out, "disk-a")
}

type errorString string

func (e errorString) Error() string { return string(e) }
