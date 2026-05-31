package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColorDecision(t *testing.T) {
	assert.False(t, ColorDecision("never", true, ""))
	assert.True(t, ColorDecision("always", false, ""))
	assert.True(t, ColorDecision("auto", true, ""))
	assert.False(t, ColorDecision("auto", false, ""), "auto off when not a tty")
	assert.False(t, ColorDecision("auto", true, "1"), "auto off when NO_COLOR set")
}

func TestColorizeGating(t *testing.T) {
	EnableColor(false)
	assert.Equal(t, "hi", colorize("#89b4fa", "hi"), "no ANSI when disabled")

	EnableColor(true)
	defer EnableColor(false)
	out := colorize("#89b4fa", "hi")
	assert.True(t, strings.HasPrefix(out, "\x1b[38;2;137;180;250m"), "truecolor prefix")
	assert.True(t, strings.HasSuffix(out, "\x1b[0m"))
	assert.Equal(t, "", colorize("#89b4fa", ""), "empty stays empty")
}

func TestStateColorFn(t *testing.T) {
	EnableColor(true)
	defer EnableColor(false)
	assert.Contains(t, stateColorFn("● started"), "\x1b[38;2;166;227;161m", "green for started")
	assert.Contains(t, stateColorFn("● stopped"), "\x1b[38;2;243;139;168m", "red for stopped")
	assert.Contains(t, stateColorFn("● maintenance"), "\x1b[38;2;249;226;175m", "yellow otherwise")
}
