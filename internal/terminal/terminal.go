package terminal

import (
	"os"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

var (
	isStdoutTerminal bool
	isStderrTerminal bool
)

func init() {
	isStdoutTerminal = isatty.IsTerminal(os.Stdout.Fd())
	isStderrTerminal = isatty.IsTerminal(os.Stderr.Fd())
}

// IsStdoutTerminal returns true if the terminal is stdout
func IsStdoutTerminal() bool {
	return isStdoutTerminal
}

// IsStderrTerminal returns true if the terminal is stderr
func IsStderrTerminal() bool {
	return isStderrTerminal
}

// GetTerminalWidth tries to figure out the width of the terminal and returns it
// returns 0 if there are problems in getting the width.
func GetTerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 0
	}
	return w
}

// GetTerminalHeight tries to figure out the height of the terminal and returns it
// returns 0 if there are problems in getting the height.
func GetTerminalHeight() int {
	_, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 0
	}
	return h
}

// GetTerminalSize returns both width and height of the terminal
// returns 0, 0 if there are problems in getting the size.
func GetTerminalSize() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 0, 0
	}
	return w, h
}
