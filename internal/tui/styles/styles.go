// Package styles holds the single lipgloss theme for the dashboard.
package styles

import (
	"image/color"

	lipgloss "charm.land/lipgloss/v2"
)

var (
	ColorAccent color.Color = lipgloss.Color("#cba6f7") // mauve
	ColorOK     color.Color = lipgloss.Color("#a6e3a1") // green
	ColorWarn   color.Color = lipgloss.Color("#f9e2af") // yellow
	ColorErr    color.Color = lipgloss.Color("#f38ba8") // red
	ColorMuted  color.Color = lipgloss.Color("#6c7086") // grey
	ColorBorder color.Color = lipgloss.Color("#313244")
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

// StateColor returns the colour for a server state string.
func StateColor(state string) color.Color {
	switch state {
	case "started":
		return ColorOK
	case "stopped", "error":
		return ColorErr
	default:
		return ColorWarn
	}
}
