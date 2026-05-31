// Package palette holds the canonical colour values shared by the CLI output
// and the TUI dashboard, so both front-ends look like one product.
package palette

const (
	Accent = "#cba6f7" // mauve — titles/headings
	Blue   = "#89b4fa" // UUIDs / identifiers
	OK     = "#a6e3a1" // green — healthy states
	Warn   = "#f9e2af" // yellow — transitional states
	Err    = "#f38ba8" // red — bad states
	Muted  = "#6c7086" // grey — secondary text, separators, dim
	Border    = "#313244"
	Selection = "#45475a" // selected-row highlight bar
)
