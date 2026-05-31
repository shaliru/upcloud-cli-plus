// Package tui implements the interactive dashboard (Bubble Tea v2).
package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"
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
	active  int // 0 = servers, 1 = storage, 2 = networks
	width   int
	height  int
	loading bool
	status  string // transient, single-line hint/feedback
	errText string // sticky full error, wrapped in the footer until acknowledged
	pending string // action awaiting confirmation: "start"/"stop"/"restart"
}

// maxErrorLines caps the wrapped error footer so a pathologically long error
// can't consume the whole screen. Typical API errors are 1–3 wrapped lines.
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

// setStartTab selects the initial tab from a resource name (e.g. "storage").
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
	if msg.String() == "enter" {
		a.network.showSelectedDetail()
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
		a.pane.detail.SetContent(renderServerDetail(msg.detail, a.detailWidth()))
		a.pane.detail.GotoTop()
		return a, nil

	case errMsg:
		a.loading = false
		a.status = ""
		a.errText = msg.err.Error()
		a.resize() // footer grows; shrink the panes to fit
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

	case storageDetailMsg:
		a.storage.setDetail(msg.detail)
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
			a.pending, a.status = "", "" // don't carry a confirm prompt across tabs
			return a, nil
		case "shift+tab":
			a.active = (a.active + 2) % 3
			a.pending, a.status = "", ""
			return a, nil
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

// footerHeight is the number of rows the error block (if any) plus the single
// status line occupy.
func (a *App) footerHeight() int {
	h := 1 // status line
	if eb := a.errorBlock(); eb != "" {
		h += strings.Count(eb, "\n") + 1
	}
	return h
}

func (a *App) resize() {
	bodyH := a.height - a.footerHeight() - 1 // -1 for the tab bar row
	if bodyH < 1 {
		bodyH = 1
	}
	a.pane.setShowIP(a.showIPColumn())
	a.pane.list.SetWidth(a.listWidth())
	a.pane.list.SetHeight(bodyH)
	a.pane.detail.SetWidth(a.detailWidth())
	a.pane.detail.SetHeight(bodyH)
	storageBodyH := bodyH - 1 // reserve a row for the storage sub-category bar
	if storageBodyH < 1 {
		storageBodyH = 1
	}
	a.storage.setSize(a.width, storageBodyH)
	a.network.setSize(a.width, bodyH)
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

	var body string
	switch a.active {
	case 0:
		body = lipglossJoin(a.pane.list.View(), a.pane.detail.View())
	case 1:
		body = a.storage.subBar() + "\n" + a.storage.view()
	default:
		body = a.network.view()
	}

	status := a.status
	if status == "" {
		status = "tab switch · [ ] storage category · ↑↓ select · enter details · s/x/r start/stop/restart · q quit"
	}
	status = truncate(status, a.width-2)

	parts := []string{tabBar, body}
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
