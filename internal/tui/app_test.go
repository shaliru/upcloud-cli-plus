package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/stretchr/testify/assert"
)

func TestApp_QuitOnQ(t *testing.T) {
	app := NewWithService(&cloud.Fake{})
	_, cmd := app.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	assert.NotNil(t, cmd)
	msg := cmd()
	_, isQuit := msg.(tea.QuitMsg)
	assert.True(t, isQuit, "pressing q should issue tea.Quit")
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

type errorString string

func (e errorString) Error() string { return string(e) }
