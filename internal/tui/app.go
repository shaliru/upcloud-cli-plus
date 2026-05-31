// Package tui implements the interactive dashboard (Bubble Tea v2).
package tui

import (
	"context"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

type ServiceFactory func(ctx context.Context) (cloud.Service, error)

type App struct {
	svc     cloud.Service
	pane    serverPane
	width   int
	height  int
	loading bool
	status  string
}

func NewWithService(svc cloud.Service) *App {
	return &App{svc: svc, pane: newServerPane(), loading: true}
}

func (a *App) Init() tea.Cmd { return a.loadServersCmd() }

func (a *App) loadServersCmd() tea.Cmd {
	return func() tea.Msg {
		servers, err := a.svc.ListServers(context.Background())
		if err != nil {
			return errMsg{err: err}
		}
		return serversLoadedMsg{servers: servers}
	}
}

func (a *App) loadDetailCmd(uuid string) tea.Cmd {
	return func() tea.Msg {
		d, err := a.svc.GetServer(context.Background(), uuid)
		if err != nil {
			return errMsg{err: err}
		}
		return serverDetailMsg{detail: d}
	}
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.resize()
		return a, nil

	case serversLoadedMsg:
		a.loading = false
		a.status = ""
		a.pane.setServers(msg.servers)
		a.resize()
		return a, nil

	case serverDetailMsg:
		a.pane.detail.SetContent(renderServerDetail(msg.detail, a.detailWidth()))
		a.pane.detail.GotoTop()
		return a, nil

	case errMsg:
		a.loading = false
		a.status = "error: " + msg.err.Error()
		return a, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "enter":
			if uuid := a.pane.selectedUUID(); uuid != "" {
				return a, a.loadDetailCmd(uuid)
			}
			return a, nil
		}
	}

	var cmd tea.Cmd
	a.pane.list, cmd = a.pane.list.Update(msg)
	return a, cmd
}

func (a *App) resize() {
	listW := a.width / 2
	bodyH := a.height - 2
	a.pane.list.SetWidth(listW)
	a.pane.list.SetHeight(bodyH)
	a.pane.detail.SetWidth(a.width - listW - 1)
	a.pane.detail.SetHeight(bodyH)
}

func (a *App) detailWidth() int {
	w := a.width - a.width/2 - 1
	if w < 1 {
		return 1
	}
	return w
}

func (a *App) viewString() string {
	if a.loading {
		return "Loading servers…"
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, a.pane.list.View(), a.pane.detail.View())
	status := a.status
	if status == "" {
		status = "↑↓ select · enter details · s/x/r start/stop/restart · q quit"
	}
	return body + "\n" + styles.StatusBar.Render(status)
}

func (a *App) View() tea.View {
	return tea.NewView(a.viewString())
}
