package output

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shaliru/upcloud-cli-plus/internal/palette"
)

// colorEnabled is package state toggled by EnableColor; default off so piped
// output and tests stay ANSI-free.
var colorEnabled bool

// EnableColor turns CLI colour on or off.
func EnableColor(on bool) { colorEnabled = on }

// ColorDecision reports whether to colourise, from the --color mode, whether
// stdout is a terminal, and the NO_COLOR env value.
func ColorDecision(mode string, isTTY bool, noColor string) bool {
	switch mode {
	case "never":
		return false
	case "always":
		return true
	default: // "auto"
		return isTTY && noColor == ""
	}
}

func hexToRGB(hex string) (int, int, int) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 255, 255, 255
	}
	r, _ := strconv.ParseInt(hex[0:2], 16, 0)
	g, _ := strconv.ParseInt(hex[2:4], 16, 0)
	b, _ := strconv.ParseInt(hex[4:6], 16, 0)
	return int(r), int(g), int(b)
}

// colorize wraps s in a truecolor foreground escape; no-op when colour is
// disabled or s is empty.
func colorize(hex, s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	r, g, b := hexToRGB(hex)
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, s)
}

func bold(s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func dim(s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

// stateColorFn colours a STATE cell (e.g. "● started") by detecting the state
// word; returns the same text wrapped in colour (width unchanged).
func stateColorFn(cell string) string {
	hex := palette.Warn
	switch {
	case strings.Contains(cell, "started"), strings.Contains(cell, "online"), strings.Contains(cell, "running"):
		hex = palette.OK
	case strings.Contains(cell, "stopped"), strings.Contains(cell, "error"):
		hex = palette.Err
	}
	return colorize(hex, cell)
}
