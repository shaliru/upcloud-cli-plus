package tui

import (
	"context"

	tea "charm.land/bubbletea/v2"
)

// Run builds a Service via the factory and runs the dashboard until the user
// quits. resource deep-links the initial tab (e.g. "storage", "network").
func Run(ctx context.Context, factory ServiceFactory, resource string) error {
	svc, err := factory(ctx)
	if err != nil {
		return err
	}
	app := NewWithService(svc)
	app.setStartTab(resource)
	p := tea.NewProgram(app)
	_, err = p.Run()
	return err
}
