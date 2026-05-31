package styles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateColor(t *testing.T) {
	assert.Equal(t, ColorOK, StateColor("started"))
	assert.Equal(t, ColorOK, StateColor("online"))
	assert.Equal(t, ColorOK, StateColor("running"))
	assert.Equal(t, ColorErr, StateColor("stopped"))
	assert.Equal(t, ColorErr, StateColor("error"))
	assert.Equal(t, ColorWarn, StateColor("maintenance"))
}
