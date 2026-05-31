package tui

import (
	"strings"
	"testing"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lipglossWidth is the display width of s (ANSI-aware).
func lipglossWidth(s string) int { return lipgloss.Width(s) }

func TestRenderServerDetail(t *testing.T) {
	d := &upcloud.ServerDetails{
		Server: upcloud.Server{
			UUID: "u1", Hostname: "web-sg-1", Title: "web-sg-1",
			Plan: "1xCPU-2GB", Zone: "sg-sin1", State: "started",
		},
		ServerGroup: "dev-md",
		Timezone:    "UTC",
	}
	out := renderServerDetail(d, 60)
	assert.Contains(t, out, "web-sg-1")
	assert.Contains(t, out, "1xCPU-2GB")
	assert.Contains(t, out, "sg-sin1")
	assert.Contains(t, out, "started")
	assert.True(t, strings.Contains(out, "Overview"))
}

func TestRenderServerDetail_Nil(t *testing.T) {
	assert.Equal(t, "", renderServerDetail(nil, 60))
}

func TestRenderServerDetail_NoLineExceedsWidth(t *testing.T) {
	d := &upcloud.ServerDetails{
		Server: upcloud.Server{
			UUID:     "00187417-b22d-4850-99f0-6b0bebb8d911",
			Hostname: "default-rdb9p-w92d7",
			Title:    "0de01bfc-a493-4f3b-8d8a-a565d5c9c81b/dev-md-sg-sin1/default-rdb9p-w92d7",
			Plan:     "PREMIUM-1xCPU-2GB", Zone: "sg-sin1", State: "started",
		},
		IPAddresses: upcloud.IPAddressSlice{
			{Address: "10.10.0.175", Access: "utility", Family: "IPv4"},
			{Address: "2a04:3543:1000:2310:607d:24ff:feef:3946", Access: "public", Family: "IPv6"},
			{Address: "94.237.73.201", Access: "public", Family: "IPv4"},
		},
	}
	const width = 50
	out := renderServerDetail(d, width)
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, lipglossWidth(line), width, "line exceeds width: %q", line)
	}
}

func TestAlignColumns_AlignsRagged(t *testing.T) {
	rows := [][]string{
		{"94.237.73.201", "public", "IPv4"},
		{"2a04:3543:1000:2310:607d:24ff:feef:3946", "public", "IPv6"},
	}
	out := alignColumns(rows, 120)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 2)
	// The "public" token starts at the same column on both rows (aligned).
	assert.Equal(t, strings.Index(lines[0], "public"), strings.Index(lines[1], "public"))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "ab…", truncate("abcdef", 3))
	assert.Equal(t, "", truncate("abc", 0))
}
