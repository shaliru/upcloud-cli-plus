// Package tui implements the interactive dashboard (Bubble Tea v2).
package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	lipgloss "charm.land/lipgloss/v2"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

type ServiceFactory func(ctx context.Context) (cloud.Service, error)

type App struct {
	svc     cloud.Service
	pane    serverPane
	storage storagePane
	network networkPane
	active  int  // 0 = servers, 1 = storage, 2 = networks
	detail  bool // false = list mode, true = full-screen detail for the active tab
	width   int
	height  int
	loading bool
	status  string
	errText string
	pending string
}

const maxErrorLines = 8

func NewWithService(svc cloud.Service) *App {
	return &App{
		svc:     svc,
		pane:    newServerPane(),
		storage: newStoragePane(),
		network: newNetworkPane(),
		loading: true,
	}
}

func (a *App) setStartTab(resource string) {
	switch resource {
	case "storage":
		a.active = 1
	case "network":
		a.active = 2
	default:
		a.active = 0
	}
}

func (a *App) Init() tea.Cmd {
	return tea.Batch(a.loadServersCmd(), a.loadIPsCmd(), a.loadStorageCmd(), a.loadNetworksCmd())
}

func (a *App) loadServersCmd() tea.Cmd {
	return func() tea.Msg {
		servers, err := a.svc.ListServers(context.Background())
		if err != nil {
			return errMsg{err: err}
		}
		return serversLoadedMsg{servers: servers}
	}
}

func (a *App) loadIPsCmd() tea.Cmd {
	return func() tea.Msg {
		ips, err := a.svc.ListIPAddresses(context.Background())
		if err != nil {
			return ipsLoadedMsg{ips: nil}
		}
		return ipsLoadedMsg{ips: ips}
	}
}

func (a *App) loadStorageCmd() tea.Cmd {
	return func() tea.Msg {
		items, err := a.svc.ListStorage(context.Background())
		if err != nil {
			return errMsg{err: err}
		}
		return storageLoadedMsg{items: items}
	}
}

func (a *App) loadNetworksCmd() tea.Cmd {
	return func() tea.Msg {
		items, err := a.svc.ListNetworks(context.Background())
		if err != nil {
			return errMsg{err: err}
		}
		return networksLoadedMsg{items: items}
	}
}

func (a *App) loadStorageDetailCmd(uuid string) tea.Cmd {
	return func() tea.Msg {
		d, err := a.svc.GetStorage(context.Background(), uuid)
		if err != nil {
			return errMsg{err: err}
		}
		return storageDetailMsg{detail: d}
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

// activeList / activeDetail return pointers to the active tab's table / viewport.
func (a *App) activeList() *table.Model {
	switch a.active {
	case 1:
		return &a.storage.list
	case 2:
		return &a.network.list
	default:
		return &a.pane.list
	}
}

func (a *App) activeDetail() *viewport.Model {
	switch a.active {
	case 1:
		return &a.storage.detail
	case 2:
		return &a.network.detail
	default:
		return &a.pane.detail
	}
}

func (a *App) updateServers(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
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
	var cmd tea.Cmd
	a.pane.list, cmd = a.pane.list.Update(msg)
	return a, cmd
}

func (a *App) updateStorage(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "]":
		a.storage.nextSub()
		return a, nil
	case "[":
		a.storage.prevSub()
		return a, nil
	case "enter":
		if uuid, ok := a.storage.selectedUUID(); ok {
			return a, a.loadStorageDetailCmd(uuid)
		}
		return a, nil
	}
	var cmd tea.Cmd
	a.storage.list, cmd = a.storage.list.Update(msg)
	return a, cmd
}

func (a *App) updateNetworks(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		a.network.toggleAll()
		return a, nil
	case "enter":
		if n, ok := a.network.selectedItem(); ok {
			a.network.detail.SetContent(renderNetworkDetail(&n, a.width))
			a.network.detail.GotoTop()
			a.detail = true
			a.resize()
		}
		return a, nil
	}
	var cmd tea.Cmd
	a.network.list, cmd = a.network.list.Update(msg)
	return a, cmd
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
		a.pane.detail.SetContent(renderServerDetail(msg.detail, a.width))
		a.pane.detail.GotoTop()
		a.detail = true
		a.resize()
		return a, nil

	case storageDetailMsg:
		a.storage.detail.SetContent(renderStorageDetail(msg.detail, a.width))
		a.storage.detail.GotoTop()
		a.detail = true
		a.resize()
		return a, nil

	case errMsg:
		a.loading = false
		a.status = ""
		a.errText = msg.err.Error()
		a.resize()
		return a, nil

	case actionDoneMsg:
		a.errText = ""
		a.status = msg.action + " ok"
		a.resize()
		return a, a.loadServersCmd()

	case storageLoadedMsg:
		a.loading = false
		a.storage.setItems(msg.items)
		a.resize()
		return a, nil

	case networksLoadedMsg:
		a.loading = false
		a.network.setItems(msg.items)
		a.resize()
		return a, nil

	case tea.KeyPressMsg:
		if a.errText != "" {
			a.errText = ""
			a.resize()
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "tab":
			a.active = (a.active + 1) % 3
			a.detail = false
			a.pending, a.status = "", ""
			a.resize()
			return a, nil
		case "shift+tab":
			a.active = (a.active + 2) % 3
			a.detail = false
			a.pending, a.status = "", ""
			a.resize()
			return a, nil
		}
		if a.detail {
			if msg.String() == "esc" {
				a.detail = false
				a.resize()
				return a, nil
			}
			var cmd tea.Cmd
			d := a.activeDetail()
			*d, cmd = d.Update(msg)
			return a, cmd
		}
		switch a.active {
		case 0:
			return a.updateServers(msg)
		case 1:
			return a.updateStorage(msg)
		default:
			return a.updateNetworks(msg)
		}
	}

	return a, nil
}

// errorBlock renders the sticky error as red, wrapped to the terminal width and
// capped at maxErrorLines. Returns "" when there is no error.
func (a *App) errorBlock() string {
	if a.errText == "" {
		return ""
	}
	style := lipgloss.NewStyle().Foreground(styles.ColorErr)
	wrapped := style.Width(maxInt(a.width, 1)).Render("error: " + a.errText)
	lines := strings.Split(wrapped, "\n")
	if len(lines) > maxErrorLines {
		lines = lines[:maxErrorLines]
		lines[maxErrorLines-1] = style.Render("… (error truncated — see CLI for full text)")
	}
	return strings.Join(lines, "\n")
}

func (a *App) footerHeight() int {
	h := 1
	if eb := a.errorBlock(); eb != "" {
		h += strings.Count(eb, "\n") + 1
	}
	return h
}

func (a *App) resize() {
	footer := a.footerHeight()
	// Always keep inactive lists at the correct width so they render correctly
	// when the tab switches. Height is set for the active pane only.
	for _, l := range []*table.Model{&a.pane.list, &a.storage.list, &a.network.list} {
		l.SetWidth(a.width)
	}
	if a.detail {
		h := a.height - 1 - footer // -1 tab bar
		if h < 1 {
			h = 1
		}
		d := a.activeDetail()
		d.SetWidth(a.width)
		d.SetHeight(h)
		return
	}
	chrome := 0
	if a.active != 0 { // storage sub-bar or network indicator
		chrome = 1
	}
	h := a.height - 1 - chrome - footer
	if h < 1 {
		h = 1
	}
	l := a.activeList()
	l.SetHeight(h)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (a *App) viewString() string {
	if a.loading {
		return "Loading…"
	}
	tabBar := renderTabs(a.active, []string{"Servers", "Storage", "Networks"})

	var middle, status string
	if a.detail {
		middle = a.activeDetail().View()
		status = "esc back · ↑↓ scroll · q quit"
	} else {
		switch a.active {
		case 0:
			middle = a.pane.listView()
		case 1:
			middle = a.storage.subBar() + "\n" + a.storage.listView()
		default:
			middle = a.network.indicator() + "\n" + a.network.listView()
		}
		if a.status != "" {
			status = a.status
		} else {
			status = "tab switch · enter details · s/x/r start/stop/restart · [ ] storage category · a all/private nets · q quit"
		}
	}
	status = truncate(status, a.width-2)

	parts := []string{tabBar, middle}
	if eb := a.errorBlock(); eb != "" {
		parts = append(parts, eb)
	}
	parts = append(parts, styles.StatusBar.Render(status))
	return strings.Join(parts, "\n")
}

func (a *App) View() tea.View {
	v := tea.NewView(a.viewString())
	v.AltScreen = true
	return v
}
