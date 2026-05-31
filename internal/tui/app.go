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

// List-pane widths sized to the columns themselves (not a fixed fraction of the
// screen), so the detail pane gets all the remaining space.
const (
	// Column content sums to 60 (no IP) / 76 (with IP); the bubbles table adds
	// ~2 cols of cell padding per column, so the pane needs headroom or the
	// rightmost column gets clipped.
	listWidthWithIP = 90 // 76 content + 5×2 padding + margin
	listWidthNoIP   = 72
	minDetailWidth  = 40
)

// showIPColumn reports whether there is room for the list to carry the PUBLIC IP
// column while still leaving a usable detail pane.
func (a *App) showIPColumn() bool {
	return a.width >= listWidthWithIP+minDetailWidth
}

func (a *App) listWidth() int {
	w := listWidthNoIP
	if a.showIPColumn() {
		w = listWidthWithIP
	}
	// The list must keep its natural column width or the table overflows; on a
	// pathologically narrow terminal, clamp to the full width instead.
	if w > a.width {
		w = a.width
	}
	return w
}

func (a *App) detailWidth() int {
	w := a.width - a.listWidth() - 1
	if w < 1 {
		return 1
	}
	return w
}

func (a *App) resize() {
	bodyH := a.height - 2
	a.pane.setShowIP(a.showIPColumn())
	a.pane.list.SetWidth(a.listWidth())
	a.pane.list.SetHeight(bodyH)
	a.pane.detail.SetWidth(a.detailWidth())
	a.pane.detail.SetHeight(bodyH)
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
	// StatusBar has 1 col of padding each side; truncate so the line never
	// overflows the terminal width.
	status = truncate(status, a.width-2)
	return body + "\n" + styles.StatusBar.Render(status)
}

func (a *App) View() tea.View {
	v := tea.NewView(a.viewString())
	v.AltScreen = true
	return v
}
