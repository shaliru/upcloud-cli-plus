package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
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
