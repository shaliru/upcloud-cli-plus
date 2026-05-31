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
	pending string // action awaiting confirmation: "start"/"stop"/"restart"
}

func NewWithService(svc cloud.Service) *App {
	return &App{svc: svc, pane: newServerPane(), loading: true}
}

func (a *App) Init() tea.Cmd { return tea.Batch(a.loadServersCmd(), a.loadIPsCmd()) }

func (a *App) loadServersCmd() tea.Cmd {
	return func() tea.Msg {
		servers, err := a.svc.ListServers(context.Background())
		if err != nil {
			return errMsg{err: err}
		}
		return serversLoadedMsg{servers: servers}
	}
}

// loadIPsCmd fetches all IP addresses in one request; failures are silent (the
// PUBLIC IP column simply stays unpopulated rather than erroring the dashboard).
func (a *App) loadIPsCmd() tea.Cmd {
	return func() tea.Msg {
		ips, err := a.svc.ListIPAddresses(context.Background())
		if err != nil {
			return ipsLoadedMsg{ips: nil}
		}
		return ipsLoadedMsg{ips: ips}
	}
}

func (a *App) actionCmd(action, uuid string) tea.Cmd {
	return func() tea.Msg {
		var err error
		switch action {
		case "start":
			err = a.svc.StartServer(context.Background(), uuid)
		case "stop":
			err = a.svc.StopServer(context.Background(), uuid)
		default:
			err = a.svc.RestartServer(context.Background(), uuid)
		}
		if err != nil {
			return errMsg{err: err}
		}
		return actionDoneMsg{action: action, ref: uuid}
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

	case ipsLoadedMsg:
		a.pane.setIPs(publicIPv4ByServer(msg.ips))
		return a, nil

	case serverDetailMsg:
		a.pane.detail.SetContent(renderServerDetail(msg.detail, a.detailWidth()))
		a.pane.detail.GotoTop()
		return a, nil

	case errMsg:
		a.loading = false
		a.status = "error: " + msg.err.Error()
		return a, nil

	case actionDoneMsg:
		a.status = msg.action + " ok"
		return a, a.loadServersCmd()

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "enter":
			if uuid := a.pane.selectedUUID(); uuid != "" {
				return a, a.loadDetailCmd(uuid)
			}
			return a, nil
		case "s", "x", "r":
			if a.pane.selectedUUID() != "" {
				a.pending = map[string]string{"s": "start", "x": "stop", "r": "restart"}[msg.String()]
				a.status = "confirm " + a.pending + "? (y/n)"
			}
			return a, nil
		case "y":
			if a.pending != "" {
				uuid := a.pane.selectedUUID()
				action := a.pending
				a.pending = ""
				a.status = action + "ing…"
				return a, a.actionCmd(action, uuid)
			}
		case "n", "esc":
			if a.pending != "" {
				a.pending = ""
				a.status = ""
				return a, nil
			}
		}
	}

	var cmd tea.Cmd
	a.pane.list, cmd = a.pane.list.Update(msg)
	return a, cmd
}

func (a *App) resize() {
	listW := a.width / 2
	bodyH := a.height - 2
	// Show the PUBLIC IP column only when the list pane is wide enough for all
	// columns (HOSTNAME+PLAN+ZONE+STATE+PUBLIC IP ≈ 76 plus cell padding).
	a.pane.setShowIP(listW >= 80)
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
	v := tea.NewView(a.viewString())
	v.AltScreen = true
	return v
}
