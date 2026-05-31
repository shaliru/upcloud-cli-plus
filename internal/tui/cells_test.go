package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUUIDCell(t *testing.T) {
	assert.Contains(t, uuidCell("u1"), "u1")
}

func TestStateCell(t *testing.T) {
	assert.Contains(t, stateCell("started"), "● started")
	assert.Equal(t, "", stateCell(""))
}

func TestTUITableStylesSelectedHasBackground(t *testing.T) {
	s := tuiTableStyles()
	assert.NotEmpty(t, s.Selected.GetBackground(), "selected row has a background")
}
