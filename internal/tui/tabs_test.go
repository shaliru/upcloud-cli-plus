package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderTabs(t *testing.T) {
	out := renderTabs(1, []string{"Servers", "Storage", "Networks"})
	assert.Contains(t, out, "Servers")
	assert.Contains(t, out, "Storage")
	assert.Contains(t, out, "Networks")
	assert.Equal(t, 0, strings.Count(out, "\n"), "tab bar is a single line")
}
