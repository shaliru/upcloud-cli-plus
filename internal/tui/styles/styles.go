// Package styles holds the single lipgloss theme for the dashboard.
package styles

import (
	"image/color"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/shaliru/upcloud-cli-plus/internal/palette"
)

var (
	ColorAccent    color.Color = lipgloss.Color(palette.Accent)
	ColorBlue      color.Color = lipgloss.Color(palette.Blue)
	ColorOK        color.Color = lipgloss.Color(palette.OK)
	ColorWarn      color.Color = lipgloss.Color(palette.Warn)
	ColorErr       color.Color = lipgloss.Color(palette.Err)
	ColorMuted     color.Color = lipgloss.Color(palette.Muted)
	ColorBorder    color.Color = lipgloss.Color(palette.Border)
	ColorSelection color.Color = lipgloss.Color(palette.Selection)
)

var (
	Title     = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
	Muted     = lipgloss.NewStyle().Foreground(ColorMuted)
	Key       = lipgloss.NewStyle().Foreground(ColorMuted)
	StatusBar = lipgloss.NewStyle().Foreground(ColorMuted).Padding(0, 1)

	Pane = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder)

	PaneFocused = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorAccent)
)

// StateColor returns the colour for a resource state string.
func StateColor(state string) color.Color {
	switch state {
	case "started", "online", "running":
		return ColorOK
	case "stopped", "error":
		return ColorErr
	default:
		return ColorWarn
	}
}
