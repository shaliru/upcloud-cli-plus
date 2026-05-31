// Package tui implements the interactive dashboard (Bubble Tea v2).
package tui

import (
	"context"

	tea "charm.land/bubbletea/v2"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
)

// ServiceFactory lazily builds a Service (matches internal/cli/server.ServiceFactory).
type ServiceFactory func(ctx context.Context) (cloud.Service, error)

// App is the root Bubble Tea model.
type App struct {
	svc    cloud.Service
	width  int
	height int
}

// NewWithService builds an App around an already-constructed Service.
func NewWithService(svc cloud.Service) *App {
	return &App{svc: svc}
}

func (a *App) Init() tea.Cmd { return nil }

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		}
	}
	return a, nil
}

func (a *App) View() tea.View {
	return tea.NewView("upctl-plus dashboard (press q to quit)")
}
