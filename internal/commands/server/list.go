package server

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands/network"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/format"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/output"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/terminal"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/ui"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/request"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TUI styles
var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("170")).
			Bold(true).
			Padding(0, 1)

	normalStyle = lipgloss.NewStyle().
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Italic(true)
)

// TUI Models
type viewType int

const (
	serverSelectionView viewType = iota
	actionMenuView
	serverDetailsView
)

type detailContentType int

const (
	overviewContent detailContentType = iota
	firewallContent
)

type tuiModel struct {
	view           viewType
	servers        []ServerItem
	selected       int
	currentServer  ServerItem
	actions        []ActionItem
	detailsOptions []string
	currentContent detailContentType
	serverDetails  *upcloud.ServerDetails
	firewallRules  *upcloud.FirewallRules
	exec           commands.Executor
	listCmd        *listCommand
	quitting       bool
	result         output.Output
	err            error
}

// ListCommand creates the "server list" command
func ListCommand() commands.Command {
	return &listCommand{
		BaseCommand: commands.New(
			"list",
			"List current servers",
			"upctl-plus server list",
			"upctl-plus server list --interactive",
			"upctl-plus server list --show-ip-addresses",
			"upctl-plus server list --show-ip-addresses=public",
		),
	}
}

type listServerIpaddresses struct {
	ServerUUID  string
	IPAddresses upcloud.IPAddressSlice
	Error       error
}

type serverWithIPAddress struct {
	upcloud.Server

	IPAddresses upcloud.IPAddressSlice `json:"ip_addresses"`
}

type serversWithIPAddresses struct {
	Servers []serverWithIPAddress `json:"servers"`
}

type listCommand struct {
	*commands.BaseCommand
	showIPAddresses string
	interactive     bool
}

// InitCommand implements Command.InitCommand
func (ls *listCommand) InitCommand() {
	accessTypes := append(append(make([]string, 0, len(network.Types)), network.Types...), "all")
	flags := &pflag.FlagSet{}
	flags.StringVar(&ls.showIPAddresses, "show-ip-addresses", "none", "Show servers IP addresses of specified access type in the output or all ip addresses if argument value is \"all\" or no argument is specified.")
	flags.Lookup("show-ip-addresses").NoOptDefVal = "all"
	flags.BoolVarP(&ls.interactive, "interactive", "i", false, "Launch interactive server selection mode")
	ls.AddFlags(flags)
	commands.Must(ls.Cobra().RegisterFlagCompletionFunc("show-ip-addresses", cobra.FixedCompletions(accessTypes, cobra.ShellCompDirectiveNoFileComp)))
}

// ExecuteWithoutArguments implements commands.NoArgumentCommand
func (ls *listCommand) ExecuteWithoutArguments(exec commands.Executor) (output.Output, error) {
	svc := exec.All()
	servers, err := svc.GetServers(exec.Context())
	if err != nil {
		return nil, err
	}

	// If interactive mode is enabled, handle server selection
	if ls.interactive {
		return ls.handleInteractiveMode(servers, exec)
	}

	rows := []output.TableRow{}
	for _, s := range servers.Servers {
		plan := s.Plan
		if plan == customPlan {
			memory := s.MemoryAmount / 1024
			plan = fmt.Sprintf("%dxCPU-%dGB (custom)", s.CoreNumber, memory)
		}

		rows = append(rows, output.TableRow{
			s.UUID,
			s.Hostname,
			plan,
			s.Zone,
			s.State,
		})
	}

	columns := []output.TableColumn{
		{Key: "uuid", Header: "UUID", Colour: ui.DefaultUUUIDColours},
		{Key: "hostname", Header: "Hostname"},
		{Key: "plan", Header: "Plan"},
		{Key: "zone", Header: "Zone"},
		{Key: "state", Header: "State", Format: format.ServerState},
	}

	if ls.showIPAddresses != "none" {
		serversWithIPs := serversWithIPAddresses{}
		ipaddressMap, err := getIPAddressesByServerUUID(servers, ls.showIPAddresses, exec)
		if err != nil {
			return nil, err
		}

		for i, row := range rows {
			uuid := row[0].(string)

			// Add IPs to the table in human output
			var listIpaddresses upcloud.IPAddressSlice
			if serverIpaddresses, ok := ipaddressMap[uuid]; ok {
				listIpaddresses = append(listIpaddresses, serverIpaddresses.IPAddresses...)
			}
			row = append(row[:3], row[2:]...)
			row[2] = listIpaddresses
			rows[i] = row

			// Add IPs to machine output
			serversWithIPs.Servers = append(serversWithIPs.Servers, serverWithIPAddress{
				Server:      servers.Servers[i],
				IPAddresses: listIpaddresses,
			})
		}
		columns = append(columns[:3], columns[2:]...)
		columns[2] = output.TableColumn{
			Key:    "ip_addresses",
			Header: "IP addresses",
			Format: formatListIPAddresses,
		}

		return output.MarshaledWithHumanOutput{
			Value: serversWithIPs,
			Output: output.Table{
				Columns: columns,
				Rows:    rows,
			},
		}, nil
	}

	return output.MarshaledWithHumanOutput{
		Value: servers,
		Output: output.Table{
			Columns: columns,
			Rows:    rows,
		},
	}, nil
}

// getIPAddressesByServerUUID returns IP addresses grouped by server UUID. This function will be removed when server end-point response includes IP addresses.
func getIPAddressesByServerUUID(servers *upcloud.Servers, accessType string, exec commands.Executor) (map[string]listServerIpaddresses, error) {
	returnChan := make(chan listServerIpaddresses)
	var wg sync.WaitGroup

	for _, server := range servers.Servers {
		wg.Add(1)
		go func(server upcloud.Server) {
			defer wg.Done()
			ipaddresses, err := getServerIPAddresses(server.UUID, accessType, exec)
			returnChan <- listServerIpaddresses{
				ServerUUID:  server.UUID,
				IPAddresses: ipaddresses,
				Error:       err,
			}
		}(server)
	}

	go func() {
		wg.Wait()
		close(returnChan)
	}()

	ipaddressMap := make(map[string]listServerIpaddresses)
	for response := range returnChan {
		ipaddressMap[response.ServerUUID] = response
	}

	return ipaddressMap, nil
}

func getServerIPAddresses(uuid, accessType string, exec commands.Executor) (upcloud.IPAddressSlice, error) {
	server, err := exec.All().GetServerNetworks(exec.Context(), &request.GetServerNetworksRequest{ServerUUID: uuid})
	if err != nil {
		return nil, err
	}

	var ipaddresses upcloud.IPAddressSlice
	for _, iface := range server.Interfaces {
		for _, ipa := range iface.IPAddresses {
			if accessType == "all" || iface.Type == accessType {
				ipa.Access = iface.Type
				ipaddresses = append(ipaddresses, ipa)
			}
		}
	}

	sort.Slice(ipaddresses, func(i, j int) bool {
		accessMap := map[string]int{
			"public":  3,
			"private": 2,
			"utility": 1,
		}
		floatingMap := map[bool]int{
			true:  1,
			false: 0,
		}

		if accessMap[ipaddresses[i].Access] != accessMap[ipaddresses[j].Access] {
			return accessMap[ipaddresses[i].Access] > accessMap[ipaddresses[j].Access]
		}

		return floatingMap[ipaddresses[i].Floating.Bool()] > floatingMap[ipaddresses[j].Floating.Bool()]
	})

	return ipaddresses, nil
}

func formatListIPAddresses(val interface{}) (text.Colors, string, error) {
	ipaddresses, ok := val.(upcloud.IPAddressSlice)
	if !ok {
		return nil, "", fmt.Errorf("cannot parse IP addresses from %T, expected upcloud.IPAddressSlice", val)
	}

	var rows []string
	for _, ipa := range ipaddresses {
		var floating string
		if ipa.Floating.Bool() {
			floating = " (f)"
		}

		rows = append(rows, fmt.Sprintf(
			"%s: %s%s",
			ipa.Access,
			ui.DefaultAddressColours.Sprint(ipa.Address),
			floating,
		))
	}

	return nil, strings.Join(rows, ",\n"), nil
}

// getServerPublicIP fetches the public IPv4 address for a server
func getServerPublicIP(uuid string, exec commands.Executor) string {
	server, err := exec.All().GetServerNetworks(exec.Context(), &request.GetServerNetworksRequest{ServerUUID: uuid})
	if err != nil {
		return "N/A"
	}

	for _, iface := range server.Interfaces {
		if iface.Type == "public" {
			for _, ip := range iface.IPAddresses {
				// Return first IPv4 public address
				if ip.Family == "IPv4" {
					return ip.Address
				}
			}
		}
	}
	return "N/A"
}

// handleInteractiveMode provides an interactive server selection interface
func (ls *listCommand) handleInteractiveMode(servers *upcloud.Servers, exec commands.Executor) (output.Output, error) {
	if len(servers.Servers) == 0 {
		return output.OnlyMarshaled{Value: "No servers found"}, nil
	}

	// Create server items for selection with IP addresses
	serverItems := make([]ServerItem, len(servers.Servers))

	// Fetch IP addresses for all servers in parallel
	type serverWithIP struct {
		index    int
		publicIP string
		err      error
	}

	ipChan := make(chan serverWithIP, len(servers.Servers))
	var wg sync.WaitGroup

	for i, server := range servers.Servers {
		wg.Add(1)
		go func(idx int, srv upcloud.Server) {
			defer wg.Done()
			publicIP := getServerPublicIP(srv.UUID, exec)
			ipChan <- serverWithIP{index: idx, publicIP: publicIP, err: nil}
		}(i, server)
	}

	go func() {
		wg.Wait()
		close(ipChan)
	}()

	// Collect IP results
	ipResults := make(map[int]string)
	for result := range ipChan {
		ipResults[result.index] = result.publicIP
	}

	// Create server items with IP addresses and pre-rendered details
	for i, server := range servers.Servers {
		plan := server.Plan
		if plan == customPlan {
			memory := server.MemoryAmount / 1024
			plan = fmt.Sprintf("%dxCPU-%dGB (custom)", server.CoreNumber, memory)
		}

		publicIP := ipResults[i]
		if publicIP == "" {
			publicIP = "N/A"
		}

		serverItems[i] = ServerItem{
			UUID:     server.UUID,
			Hostname: server.Hostname,
			Plan:     plan,
			Zone:     server.Zone,
			State:    server.State,
			PublicIP: publicIP,
			Server:   server,
		}
	}

	// Initialize Bubble Tea TUI
	model := tuiModel{
		view:     serverSelectionView,
		servers:  serverItems,
		selected: 0,
		exec:     exec,
		listCmd:  ls,
	}

	p := tea.NewProgram(model)
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("TUI error: %w", err)
	}

	m := finalModel.(tuiModel)
	if m.err != nil {
		return nil, m.err
	}

	// Handle special cases
	if m.result != nil {
		// Check if this is a delete confirmation
		if marshaled, ok := m.result.(output.OnlyMarshaled); ok {
			if value, ok := marshaled.Value.(string); ok && strings.HasPrefix(value, "delete_confirm:") {
				uuid := strings.TrimPrefix(value, "delete_confirm:")
				return ls.handleDeleteConfirmation(uuid, exec)
			}
		}
		return m.result, nil
	}

	return output.OnlyMarshaled{Value: "Interactive mode exited."}, nil
}

// ServerItem represents a server for selection display
type ServerItem struct {
	UUID     string
	Hostname string
	Plan     string
	Zone     string
	State    string
	PublicIP string
	Server   upcloud.Server
}

// TUI Methods
func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.view == serverSelectionView {
				if m.selected > 0 {
					m.selected--
				}
			} else if m.view == actionMenuView {
				if m.selected > 0 {
					m.selected--
				}
			} else if m.view == serverDetailsView {
				if m.selected > 0 {
					m.selected--
				}
			}
		case "down", "j":
			if m.view == serverSelectionView {
				if m.selected < len(m.servers)-1 {
					m.selected++
				}
			} else if m.view == actionMenuView {
				if m.selected < len(m.actions)-1 {
					m.selected++
				}
			} else if m.view == serverDetailsView {
				if m.selected < len(m.detailsOptions)-1 {
					m.selected++
				}
			}
		case "enter":
			switch m.view {
			case serverSelectionView:
				m.currentServer = m.servers[m.selected]
				m.actions = m.getActionsForServer(m.currentServer)
				m.view = actionMenuView
				m.selected = 0
			case actionMenuView:
				action := m.actions[m.selected]
				return m.executeAction(action)
			case serverDetailsView:
				// Handle details navigation options
				return m.handleDetailsNavigation()
			}
		case "esc":
			if m.view == actionMenuView {
				m.view = serverSelectionView
				m.selected = 0
			} else if m.view == serverDetailsView {
				m.view = actionMenuView
				m.selected = 0
			}
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.quitting {
		return ""
	}

	switch m.view {
	case serverSelectionView:
		return m.renderServerSelection()
	case actionMenuView:
		return m.renderActionMenu()
	case serverDetailsView:
		return m.renderServerDetails()
	default:
		return "Unknown view"
	}
}

func (m tuiModel) renderServerSelection() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("🖥️  Server Selection"))
	b.WriteString("\n\n")

	// Header
	b.WriteString(fmt.Sprintf("%-38s %-25s %-23s %-9s %-9s %s\n",
		"UUID", "Hostname", "Plan", "Zone", "State", "Public IPv4"))
	b.WriteString(strings.Repeat("─", 130))
	b.WriteString("\n")

	// Server list
	for i, server := range m.servers {
		line := fmt.Sprintf("%-38s %-25s %-23s %-9s %-9s %s",
			server.UUID, server.Hostname, server.Plan, server.Zone, server.State, server.PublicIP)

		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + line))
		} else {
			b.WriteString(normalStyle.Render("  " + line))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate • enter: select • q/ctrl+c: quit"))
	return b.String()
}

func (m tuiModel) renderActionMenu() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render(fmt.Sprintf("⚡ Actions for %s (%s)", m.currentServer.Hostname, m.currentServer.State)))
	b.WriteString("\n\n")

	for i, action := range m.actions {
		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + action.Name))
		} else {
			b.WriteString(normalStyle.Render("  " + action.Name))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate • enter: select • esc: back • q/ctrl+c: quit"))
	return b.String()
}

func (m tuiModel) renderServerDetails() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render(fmt.Sprintf("📊 Server Details: %s", m.currentServer.Hostname)))
	b.WriteString("\n\n")

	// Render content based on current selection
	switch m.currentContent {
	case overviewContent:
		b.WriteString(m.renderOverviewContent())
	case firewallContent:
		b.WriteString(m.renderFirewallContent())
	}

	// Navigation options
	b.WriteString(headerStyle.Render("Navigation Options:"))
	b.WriteString("\n")

	for i, option := range m.detailsOptions {
		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + option))
		} else {
			b.WriteString(normalStyle.Render("  " + option))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate options • enter: select • esc: back to actions • q/ctrl+c: quit"))
	return b.String()
}

// renderOverviewContent renders the server overview (common info, storage, network)
func (m tuiModel) renderOverviewContent() string {
	var b strings.Builder

	// Common Information Section
	commonTable := m.createDetailTable()
	commonTable.SetTitle("Common Information")

	planOutput := m.serverDetails.Plan
	if planOutput == customPlan {
		memory := m.serverDetails.MemoryAmount / 1024
		planOutput = fmt.Sprintf("%dxCPU-%dGB (custom)", m.serverDetails.CoreNumber, memory)
	}

	commonTable.AppendRow([]interface{}{"UUID:", m.serverDetails.UUID})
	commonTable.AppendRow([]interface{}{"Hostname:", m.serverDetails.Hostname})
	commonTable.AppendRow([]interface{}{"Title:", m.serverDetails.Title})
	commonTable.AppendRow([]interface{}{"Plan:", planOutput})
	commonTable.AppendRow([]interface{}{"Zone:", m.serverDetails.Zone})
	commonTable.AppendRow([]interface{}{"State:", m.serverDetails.State})
	commonTable.AppendRow([]interface{}{"Simple Backup:", m.serverDetails.SimpleBackup})
	commonTable.AppendRow([]interface{}{"License:", m.serverDetails.License})
	commonTable.AppendRow([]interface{}{"Metadata:", m.serverDetails.Metadata.String()})
	commonTable.AppendRow([]interface{}{"Timezone:", m.serverDetails.Timezone})
	commonTable.AppendRow([]interface{}{"Host ID:", fmt.Sprintf("%d", m.serverDetails.Host)})
	commonTable.AppendRow([]interface{}{"Server Group:", m.serverDetails.ServerGroup})
	commonTable.AppendRow([]interface{}{"Tags:", strings.Join(m.serverDetails.Tags, ", ")})

	b.WriteString(commonTable.Render())
	b.WriteString("\n")

	// Storage Devices Section
	if len(m.serverDetails.StorageDevices) > 0 {
		storageTable := m.createDetailTable()
		storageTable.SetTitle("Storage Devices (Flags: B = bootdisk, P = part of plan)")
		storageTable.AppendHeader([]interface{}{"Title", "Type", "Size (GB)", "Address", "Encrypted", "Flags"})

		for _, storage := range m.serverDetails.StorageDevices {
			var flags []string
			if storage.PartOfPlan == "yes" {
				flags = append(flags, "P")
			}
			if storage.BootDisk == 1 {
				flags = append(flags, "B")
			}

			storageTable.AppendRow([]interface{}{
				storage.Title,
				storage.Type,
				storage.Size,
				storage.Address,
				storage.Encrypted,
				strings.Join(flags, " "),
			})
		}

		b.WriteString(storageTable.Render())
		b.WriteString("\n")
	}

	// Network Interfaces Section
	if len(m.serverDetails.Networking.Interfaces) > 0 {
		nicTable := m.createDetailTable()
		nicTable.SetTitle("Network Interfaces (Flags: S = source IP filtering, B = bootable)")
		nicTable.AppendHeader([]interface{}{"#", "Type", "IP Address", "MAC Address", "Network", "Flags"})

		// Get terminal width for responsive column sizing
		termWidth := terminal.GetTerminalWidth()
		if termWidth <= 0 {
			termWidth = 80
		}

		// Set responsive column configurations based on terminal width
		if termWidth < 120 {
			// Narrow terminal - use compact column widths
			nicTable.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 2, WidthMin: 1},   // # column
				{Number: 2, WidthMax: 7, WidthMin: 6},   // Type column
				{Number: 3, WidthMax: 30, WidthMin: 15}, // IP Address column - truncated for narrow terminals
				{Number: 4, WidthMax: 17, WidthMin: 17}, // MAC Address column
				{Number: 5, WidthMax: 20, WidthMin: 10}, // Network column - truncated
				{Number: 6, WidthMax: 5, WidthMin: 1},   // Flags column
			})
		} else {
			// Wide terminal - use full column widths
			nicTable.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 3, WidthMin: 1},   // # column
				{Number: 2, WidthMax: 8, WidthMin: 6},   // Type column
				{Number: 3, WidthMax: 45, WidthMin: 20}, // IP Address column
				{Number: 4, WidthMax: 18, WidthMin: 17}, // MAC Address column
				{Number: 5, WidthMax: 36, WidthMin: 20}, // Network column
				{Number: 6, WidthMax: 6, WidthMin: 1},   // Flags column
			})
		}

		for _, nic := range m.serverDetails.Networking.Interfaces {
			var flags []string
			if nic.SourceIPFiltering.Bool() {
				flags = append(flags, "S")
			}
			if nic.Bootable.Bool() {
				flags = append(flags, "B")
			}

			// Format IP addresses
			var ipStrings []string
			for _, ip := range nic.IPAddresses {
				ipStrings = append(ipStrings, fmt.Sprintf("%s: %s", ip.Family, ip.Address))
			}

			nicTable.AppendRow([]interface{}{
				nic.Index,
				nic.Type,
				strings.Join(ipStrings, ", "),
				nic.MAC,
				nic.Network,
				strings.Join(flags, " "),
			})
		}

		b.WriteString(nicTable.Render())
		b.WriteString("\n")
	}

	return b.String()
}

// renderFirewallContent renders the firewall rules table
func (m tuiModel) renderFirewallContent() string {
	var b strings.Builder

	if m.serverDetails.Firewall == "on" && m.firewallRules != nil && len(m.firewallRules.FirewallRules) > 0 {
		fwTable := m.createDetailTable()
		fwTable.SetTitle("Firewall Rules")
		fwTable.AppendHeader([]interface{}{"#", "Direction", "Action", "Src IP", "Dest IP", "Src Port", "Dest Port", "Protocol"})

		// Get terminal width for responsive column sizing
		termWidth := terminal.GetTerminalWidth()
		if termWidth <= 0 {
			termWidth = 80
		}

		// Set responsive column configurations based on terminal width
		if termWidth < 140 {
			// Narrow terminal - use compact column widths
			fwTable.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 3, WidthMin: 1},  // # column
				{Number: 2, WidthMax: 9, WidthMin: 3},  // Direction column
				{Number: 3, WidthMax: 6, WidthMin: 4},  // Action column
				{Number: 4, WidthMax: 12, WidthMin: 3}, // Src IP column - truncated
				{Number: 5, WidthMax: 12, WidthMin: 3}, // Dest IP column - truncated
				{Number: 6, WidthMax: 8, WidthMin: 3},  // Src Port column
				{Number: 7, WidthMax: 8, WidthMin: 3},  // Dest Port column
				{Number: 8, WidthMax: 10, WidthMin: 4}, // Protocol column
			})
		} else {
			// Wide terminal - use full column widths
			fwTable.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 4, WidthMin: 1},  // # column
				{Number: 2, WidthMax: 11, WidthMin: 9}, // Direction column
				{Number: 3, WidthMax: 8, WidthMin: 6},  // Action column
				{Number: 4, WidthMax: 17, WidthMin: 7}, // Src IP column
				{Number: 5, WidthMax: 13, WidthMin: 7}, // Dest IP column
				{Number: 6, WidthMax: 10, WidthMin: 6}, // Src Port column
				{Number: 7, WidthMax: 11, WidthMin: 6}, // Dest Port column
				{Number: 8, WidthMax: 10, WidthMin: 8}, // Protocol column
			})
		}

		for _, rule := range m.firewallRules.FirewallRules {
			// Format IP address ranges
			srcIP := m.formatIPRange(rule.SourceAddressStart, rule.SourceAddressEnd)
			destIP := m.formatIPRange(rule.DestinationAddressStart, rule.DestinationAddressEnd)
			srcPort := m.formatPortRange(rule.SourcePortStart, rule.SourcePortEnd)
			destPort := m.formatPortRange(rule.DestinationPortStart, rule.DestinationPortEnd)

			fwTable.AppendRow([]interface{}{
				rule.Position,
				rule.Direction,
				rule.Action,
				srcIP,
				destIP,
				srcPort,
				destPort,
				rule.Family + "/" + rule.Protocol,
			})
		}

		b.WriteString(fwTable.Render())
		b.WriteString("\n")
	} else {
		// Handle case where firewall is disabled or no rules
		b.WriteString("Firewall is disabled or no rules configured.\n")
	}

	return b.String()
}

// createDetailTable creates a table optimized for TUI display
func (m tuiModel) createDetailTable() table.Writer {
	t := table.NewWriter()

	// Get terminal width and calculate available space
	termWidth := terminal.GetTerminalWidth()
	if termWidth <= 0 {
		termWidth = 80 // Default fallback width
	}

	// Use a simple style that works well in narrow terminals
	t.SetStyle(table.Style{
		Name: "TUISimple",
		Box: table.BoxStyle{
			BottomLeft:       "└",
			BottomRight:      "┘",
			BottomSeparator:  "┴",
			Left:             "│",
			LeftSeparator:    "├",
			MiddleHorizontal: "─",
			MiddleSeparator:  "┼",
			MiddleVertical:   "│",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			Right:            "│",
			RightSeparator:   "┤",
			TopLeft:          "┌",
			TopRight:         "┐",
			TopSeparator:     "┬",
			UnfinishedRow:    " ",
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	})

	// Set table width to be responsive to terminal width
	// Leave some margin (4 chars) for better readability
	maxTableWidth := termWidth - 4
	if maxTableWidth < 60 {
		maxTableWidth = 60 // Minimum usable width
	}

	t.SetAllowedRowLength(maxTableWidth)

	return t
}

// formatIPRange formats IP address ranges for display
func (m tuiModel) formatIPRange(start, end string) string {
	if start == "" && end == "" {
		return "Any"
	}
	if start == end {
		return start
	}
	return fmt.Sprintf("%s-%s", start, end)
}

// formatPortRange formats port ranges for display
func (m tuiModel) formatPortRange(start, end string) string {
	if start == "" && end == "" {
		return "Any"
	}
	if start == end {
		return start
	}
	return fmt.Sprintf("%s-%s", start, end)
}

func (m tuiModel) handleDetailsNavigation() (tea.Model, tea.Cmd) {
	selectedOption := m.detailsOptions[m.selected]

	switch selectedOption {
	case "Server overview":
		m.currentContent = overviewContent
		return m, nil
	case "Firewall rules":
		m.currentContent = firewallContent
		return m, nil
	case "Back to actions":
		m.view = actionMenuView
		m.selected = 0
		return m, nil
	case "Back to server list":
		m.view = serverSelectionView
		m.selected = 0
		return m, nil
	default:
		return m, nil
	}
}

func (m tuiModel) getActionsForServer(server ServerItem) []ActionItem {
	actions := []ActionItem{
		{Name: "Show details", Command: "show", Enabled: true},
		{Name: "Start server", Command: "start", Enabled: server.State == "stopped"},
		{Name: "Restart server", Command: "restart", Enabled: server.State == "started"},
		{Name: "Stop server", Command: "stop", Enabled: server.State == "started"},
		{Name: "Delete server", Command: "delete", Enabled: server.State == "stopped"},
		{Name: "Back to server list", Command: "back", Enabled: true},
		{Name: "Exit", Command: "exit", Enabled: true},
	}

	// Filter enabled actions
	var enabledActions []ActionItem
	for _, action := range actions {
		if action.Enabled {
			enabledActions = append(enabledActions, action)
		}
	}

	return enabledActions
}

func (m tuiModel) executeAction(action ActionItem) (tea.Model, tea.Cmd) {
	switch action.Command {
	case "show":
		// Load server details and firewall rules
		details, err := m.exec.All().GetServerDetails(m.exec.Context(), &request.GetServerDetailsRequest{UUID: m.currentServer.UUID})
		if err != nil {
			m.err = err
			m.quitting = true
			return m, tea.Quit
		}
		m.serverDetails = details

		// Load firewall rules if firewall is enabled
		if details.Firewall == "on" {
			fwRules, fwErr := m.exec.All().GetFirewallRules(m.exec.Context(), &request.GetFirewallRulesRequest{ServerUUID: m.currentServer.UUID})
			if fwErr == nil {
				m.firewallRules = fwRules
			}
		}

		// Build navigation options dynamically
		m.detailsOptions = []string{"Server overview"}

		// Only add firewall option if firewall is enabled and has rules
		if details.Firewall == "on" && m.firewallRules != nil && len(m.firewallRules.FirewallRules) > 0 {
			m.detailsOptions = append(m.detailsOptions, "Firewall rules")
		}

		// Add standard navigation options (removed "Exit" as requested)
		m.detailsOptions = append(m.detailsOptions, []string{
			"Back to actions",
			"Back to server list",
		}...)

		m.currentContent = overviewContent // Start with overview
		m.view = serverDetailsView
		m.selected = 0
		return m, nil
	case "start":
		startCmd := StartCommand().(*startCommand)
		result, err := startCmd.Execute(m.exec, m.currentServer.UUID)
		m.result = result
		m.err = err
		m.quitting = true
		return m, tea.Quit
	case "restart":
		restartCmd := RestartCommand().(*restartCommand)
		result, err := restartCmd.Execute(m.exec, m.currentServer.UUID)
		m.result = result
		m.err = err
		m.quitting = true
		return m, tea.Quit
	case "stop":
		stopCmd := StopCommand().(*stopCommand)
		result, err := stopCmd.Execute(m.exec, m.currentServer.UUID)
		m.result = result
		m.err = err
		m.quitting = true
		return m, tea.Quit
	case "delete":
		// For delete, we'll quit TUI and handle confirmation outside
		m.result = output.OnlyMarshaled{Value: "delete_confirm:" + m.currentServer.UUID}
		m.quitting = true
		return m, tea.Quit
	case "back":
		m.view = serverSelectionView
		m.selected = 0
		return m, nil
	case "exit":
		m.quitting = true
		return m, tea.Quit
	default:
		m.err = fmt.Errorf("unknown action: %s", action.Command)
		m.quitting = true
		return m, tea.Quit
	}
}

// handleDeleteConfirmation handles server deletion with confirmation
func (ls *listCommand) handleDeleteConfirmation(uuid string, exec commands.Executor) (output.Output, error) {
	// Get server details for confirmation
	servers, err := exec.All().GetServers(exec.Context())
	if err != nil {
		return nil, err
	}

	var serverName string
	for _, server := range servers.Servers {
		if server.UUID == uuid {
			serverName = server.Hostname
			break
		}
	}

	if serverName == "" {
		return nil, fmt.Errorf("server not found")
	}

	// Simple confirmation prompt
	fmt.Printf("\n⚠️  WARNING: Are you sure you want to delete %s?\n", serverName)
	fmt.Printf("This action cannot be undone. Type 'yes' to confirm: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return output.OnlyMarshaled{Value: "Deletion cancelled"}, nil
	}

	input = strings.TrimSpace(input)
	if input != "yes" {
		fmt.Printf("\nDeletion cancelled.\n")
		return output.OnlyMarshaled{Value: "Deletion cancelled"}, nil
	}

	deleteCmd := DeleteCommand().(*deleteCommand)
	return deleteCmd.Execute(exec, uuid)
}

// handleShowDetailsAndReturn shows server details and returns to TUI
func (ls *listCommand) handleShowDetailsAndReturn(uuid string, servers *upcloud.Servers, exec commands.Executor) (output.Output, error) {
	// Find the server
	var serverItem ServerItem
	for _, server := range servers.Servers {
		if server.UUID == uuid {
			plan := server.Plan
			if plan == customPlan {
				memory := server.MemoryAmount / 1024
				plan = fmt.Sprintf("%dxCPU-%dGB (custom)", server.CoreNumber, memory)
			}

			publicIP := getServerPublicIP(server.UUID, exec)
			if publicIP == "" {
				publicIP = "N/A"
			}

			serverItem = ServerItem{
				UUID:     server.UUID,
				Hostname: server.Hostname,
				Plan:     plan,
				Zone:     server.Zone,
				State:    server.State,
				PublicIP: publicIP,
				Server:   server,
			}
			break
		}
	}

	if serverItem.UUID == "" {
		return nil, fmt.Errorf("server not found")
	}

	// Show details without the "Press Enter to continue" and old menu
	ls.showDetailsOnly(serverItem, exec)

	// Ask user what to do next
	fmt.Printf("\n\n[1] Back to server actions  [2] Back to server list  [3] Exit\n")
	fmt.Printf("Choose option (1-3): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return output.OnlyMarshaled{Value: "Interactive mode cancelled"}, nil
	}

	input = strings.TrimSpace(input)
	switch input {
	case "1":
		// Return to action menu for this server - restart TUI with action view
		return ls.handleInteractiveMode(servers, exec)
	case "2":
		// Return to server list
		return ls.handleInteractiveMode(servers, exec)
	case "3":
		// Exit
		return output.OnlyMarshaled{Value: "Interactive mode exited."}, nil
	default:
		// Invalid choice, return to server list
		fmt.Printf("Invalid choice. Returning to server list.\n")
		return ls.handleInteractiveMode(servers, exec)
	}
}

// showDetailsOnly displays server information without interactive prompts
func (ls *listCommand) showDetailsOnly(server ServerItem, exec commands.Executor) {
	// Get full server details
	fullServer, err := exec.All().GetServerDetails(exec.Context(), &request.GetServerDetailsRequest{UUID: server.UUID})
	if err != nil {
		fmt.Printf("Error getting server details: %v\n", err)
		return
	}

	fmt.Printf("\n")

	// Common Information Table
	commonTable := createBoxedTable()
	commonTable.SetTitle("Server Information")
	commonTable.AppendRow([]interface{}{"UUID", fullServer.UUID})
	commonTable.AppendRow([]interface{}{"Hostname", fullServer.Hostname})
	commonTable.AppendRow([]interface{}{"Title", fullServer.Title})
	commonTable.AppendRow([]interface{}{"Plan", fullServer.Plan})
	commonTable.AppendRow([]interface{}{"Zone", fullServer.Zone})
	commonTable.AppendRow([]interface{}{"State", fullServer.State})
	commonTable.AppendRow([]interface{}{"CPU Cores", fmt.Sprintf("%d", fullServer.CoreNumber)})
	commonTable.AppendRow([]interface{}{"Memory", fmt.Sprintf("%d MB", fullServer.MemoryAmount)})
	commonTable.AppendRow([]interface{}{"Host ID", fmt.Sprintf("%d", fullServer.Host)})
	commonTable.AppendRow([]interface{}{"Timezone", fullServer.Timezone})
	if fullServer.SimpleBackup == "yes" {
		commonTable.AppendRow([]interface{}{"Simple Backup", "Enabled"})
	} else {
		commonTable.AppendRow([]interface{}{"Simple Backup", "Disabled"})
	}

	fmt.Println(commonTable.Render())
	fmt.Println()

	// Network Interfaces Table
	if len(fullServer.Networking.Interfaces) > 0 {
		nicTable := createBoxedTable()
		nicTable.SetTitle("Network Interfaces")
		nicTable.AppendHeader([]interface{}{"#", "Type", "IP Address", "MAC Address", "Network"})

		// Set compact column widths for Network Interfaces
		nicTable.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 3, WidthMin: 1},   // # column - just needs 1-3 chars
			{Number: 2, WidthMax: 8, WidthMin: 4},   // Type column - "public", "private", "utility"
			{Number: 3, WidthMax: 45, WidthMin: 40}, // IP Address column - fits "IPv6: 2a04:3543:1000:2310:607d:24ff:feef:3946"
			{Number: 4, WidthMax: 18, WidthMin: 17}, // MAC Address column (standard MAC length)
			{Number: 5, WidthMax: 36, WidthMin: 36}, // Network column - fits UUID "03000000-0000-4000-8083-000000000000"
		})

		for i, iface := range fullServer.Networking.Interfaces {
			for _, ip := range iface.IPAddresses {
				nicTable.AppendRow([]interface{}{
					i + 1,
					iface.Type,
					fmt.Sprintf("%s: %s", ip.Family, ip.Address),
					iface.MAC,
					iface.Network,
				})
			}
		}

		fmt.Println(nicTable.Render())
		fmt.Println()
	}

	// Storage Devices Table
	if len(fullServer.StorageDevices) > 0 {
		storageTable := createBoxedTable()
		storageTable.SetTitle("Storage Devices")
		storageTable.AppendHeader([]interface{}{"UUID", "Title", "Size (GB)", "Type", "Address"})

		// Set optimized column widths for Storage Devices
		storageTable.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 36, WidthMin: 36}, // UUID column - fits "0100d1f1-1a35-4a48-af83-affd557f03f0"
			{Number: 2, WidthMax: 36, WidthMin: 20}, // Title column - same max width as UUID, flexible min
			{Number: 3, WidthMax: 10, WidthMin: 8},  // Size (GB) column - compact for numbers
			{Number: 4, WidthMax: 12, WidthMin: 8},  // Type column - compact for storage types
			{Number: 5, WidthMax: 15, WidthMin: 10}, // Address column - compact for addresses like "virtio:0"
		})

		for _, storage := range fullServer.StorageDevices {
			storageTable.AppendRow([]interface{}{
				storage.UUID,
				storage.Title,
				storage.Size,
				storage.Type,
				storage.Address,
			})
		}

		fmt.Println(storageTable.Render())
		fmt.Println()
	}

	// Tags Table (if any)
	if len(fullServer.Tags) > 0 {
		tagsTable := createBoxedTable()
		tagsTable.SetTitle("Tags")
		for _, tag := range fullServer.Tags {
			tagsTable.AppendRow([]interface{}{tag})
		}

		fmt.Println(tagsTable.Render())
		fmt.Println()
	}
}

// showActionMenu displays available actions for the selected server
func (ls *listCommand) showActionMenu(server ServerItem, exec commands.Executor) (output.Output, error) {
	// Show selected server summary in a beautiful table
	fmt.Printf("\n\n") // Add some spacing

	// Create a beautiful server summary table
	summaryTable := createBoxedTable()
	summaryTable.SetTitle("Selected Server")
	summaryTable.AppendRow([]interface{}{"Hostname", server.Hostname})
	summaryTable.AppendRow([]interface{}{"UUID", server.UUID})
	summaryTable.AppendRow([]interface{}{"State", server.State})
	summaryTable.AppendRow([]interface{}{"Zone", server.Zone})
	summaryTable.AppendRow([]interface{}{"Plan", server.Plan})
	summaryTable.AppendRow([]interface{}{"Public IP", server.PublicIP})

	fmt.Println(summaryTable.Render())
	fmt.Println()

	actions := []ActionItem{
		{Name: "Show details", Command: "show", Enabled: true},
		{Name: "Start server", Command: "start", Enabled: server.State == "stopped"},
		{Name: "Restart server", Command: "restart", Enabled: server.State == "started"},
		{Name: "Stop server", Command: "stop", Enabled: server.State == "started"},
		{Name: "Delete server", Command: "delete", Enabled: server.State == "stopped"},
		{Name: "Back to server list", Command: "back", Enabled: true},
		{Name: "Exit", Command: "exit", Enabled: true},
	}

	// Filter enabled actions and display menu
	var enabledActions []ActionItem
	for _, action := range actions {
		if action.Enabled {
			enabledActions = append(enabledActions, action)
		}
	}

	fmt.Printf("=== Actions for %s (%s) ===\n\n", server.Hostname, server.State)
	for i, action := range enabledActions {
		fmt.Printf("%d. %s\n", i+1, action.Name)
	}

	fmt.Printf("\nEnter action number (1-%d) or 'q' to quit: ", len(enabledActions))

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("\nAction selection cancelled.\n")
		return output.OnlyMarshaled{Value: ""}, nil
	}

	input = strings.TrimSpace(input)
	if input == "q" || input == "quit" {
		fmt.Printf("\nExiting interactive mode.\n")
		return output.OnlyMarshaled{Value: ""}, nil
	}

	index, err := strconv.Atoi(input)
	if err != nil || index < 1 || index > len(enabledActions) {
		fmt.Printf("\nInvalid selection. Please try again.\n")
		return ls.showActionMenu(server, exec)
	}

	index-- // Convert to 0-based index

	selectedAction := enabledActions[index]

	// Execute the selected action
	return ls.executeAction(selectedAction, server, exec)
}

// ActionItem represents an available action
type ActionItem struct {
	Name    string
	Command string
	Enabled bool
}

// createBoxedTable creates a table with a nice boxed style and responsive width
func createBoxedTable() table.Writer {
	t := table.NewWriter()
	t.SetStyle(table.Style{
		Name: "ServerDetails",
		Box: table.BoxStyle{
			BottomLeft:       "┗",
			BottomRight:      "┛",
			BottomSeparator:  "┻",
			Left:             "┃",
			LeftSeparator:    "┣",
			MiddleHorizontal: "━",
			MiddleSeparator:  "╋",
			MiddleVertical:   "┃",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			Right:            "┃",
			RightSeparator:   "┫",
			TopLeft:          "┏",
			TopRight:         "┓",
			TopSeparator:     "┳",
			UnfinishedRow:    " ",
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	})

	// Get terminal width and set responsive column widths
	termWidth := terminal.GetTerminalWidth()
	if termWidth <= 0 {
		termWidth = 80 // Default fallback width
	}

	// Calculate responsive column widths
	maxTableWidth := termWidth - 4 // Leave margin for borders
	if maxTableWidth < 60 {
		maxTableWidth = 60 // Minimum usable width
	}

	// Set responsive column widths - roughly 20% for labels, 80% for values
	labelWidth := maxTableWidth / 5
	if labelWidth < 10 {
		labelWidth = 10
	}
	if labelWidth > 20 {
		labelWidth = 20
	}

	valueWidth := maxTableWidth - labelWidth - 4 // Account for borders and padding
	if valueWidth < 20 {
		valueWidth = 20
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: labelWidth, WidthMin: 10}, // Responsive width for labels
		{Number: 2, WidthMax: valueWidth, WidthMin: 20}, // Responsive width for values
	})

	t.SetAllowedRowLength(maxTableWidth)

	return t
}

// showEnhancedServerDetails displays server information in beautiful ASCII tables
func (ls *listCommand) showEnhancedServerDetails(server ServerItem, exec commands.Executor) (output.Output, error) {
	// Get full server details
	fullServer, err := exec.All().GetServerDetails(exec.Context(), &request.GetServerDetailsRequest{UUID: server.UUID})
	if err != nil {
		return nil, err
	}

	// Show enhanced details
	fmt.Printf("\n\n") // Add some spacing

	// Common Information Table
	commonTable := createBoxedTable()
	commonTable.SetTitle("Server Information")
	commonTable.AppendRow([]interface{}{"UUID", fullServer.UUID})
	commonTable.AppendRow([]interface{}{"Hostname", fullServer.Hostname})
	commonTable.AppendRow([]interface{}{"Title", fullServer.Title})
	commonTable.AppendRow([]interface{}{"Plan", fullServer.Plan})
	commonTable.AppendRow([]interface{}{"Zone", fullServer.Zone})
	commonTable.AppendRow([]interface{}{"State", fullServer.State})
	commonTable.AppendRow([]interface{}{"CPU Cores", fmt.Sprintf("%d", fullServer.CoreNumber)})
	commonTable.AppendRow([]interface{}{"Memory", fmt.Sprintf("%d MB", fullServer.MemoryAmount)})
	commonTable.AppendRow([]interface{}{"Host ID", fmt.Sprintf("%d", fullServer.Host)})
	commonTable.AppendRow([]interface{}{"Timezone", fullServer.Timezone})
	if fullServer.SimpleBackup == "yes" {
		commonTable.AppendRow([]interface{}{"Simple Backup", "Enabled"})
	} else {
		commonTable.AppendRow([]interface{}{"Simple Backup", "Disabled"})
	}

	fmt.Println(commonTable.Render())
	fmt.Println()

	// Network Interfaces Table
	if len(fullServer.Networking.Interfaces) > 0 {
		nicTable := createBoxedTable()
		nicTable.SetTitle("Network Interfaces")
		nicTable.AppendHeader([]interface{}{"#", "Type", "IP Address", "MAC Address", "Network"})

		// Set compact column widths for Network Interfaces
		nicTable.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 3, WidthMin: 1},   // # column - just needs 1-3 chars
			{Number: 2, WidthMax: 8, WidthMin: 4},   // Type column - "public", "private", "utility"
			{Number: 3, WidthMax: 45, WidthMin: 40}, // IP Address column - fits "IPv6: 2a04:3543:1000:2310:607d:24ff:feef:3946"
			{Number: 4, WidthMax: 18, WidthMin: 17}, // MAC Address column (standard MAC length)
			{Number: 5, WidthMax: 36, WidthMin: 36}, // Network column - fits UUID "03000000-0000-4000-8083-000000000000"
		})

		for i, iface := range fullServer.Networking.Interfaces {
			for _, ip := range iface.IPAddresses {
				nicTable.AppendRow([]interface{}{
					i + 1,
					iface.Type,
					fmt.Sprintf("%s: %s", ip.Family, ip.Address),
					iface.MAC,
					iface.Network,
				})
			}
		}

		fmt.Println(nicTable.Render())
		fmt.Println()
	}

	// Storage Devices Table
	if len(fullServer.StorageDevices) > 0 {
		storageTable := createBoxedTable()
		storageTable.SetTitle("Storage Devices")
		storageTable.AppendHeader([]interface{}{"UUID", "Title", "Size (GB)", "Type", "Address"})

		// Set optimized column widths for Storage Devices
		storageTable.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 36, WidthMin: 36}, // UUID column - fits "0100d1f1-1a35-4a48-af83-affd557f03f0"
			{Number: 2, WidthMax: 36, WidthMin: 20}, // Title column - same max width as UUID, flexible min
			{Number: 3, WidthMax: 10, WidthMin: 8},  // Size (GB) column - compact for numbers
			{Number: 4, WidthMax: 12, WidthMin: 8},  // Type column - compact for storage types
			{Number: 5, WidthMax: 15, WidthMin: 10}, // Address column - compact for addresses like "virtio:0"
		})

		for _, storage := range fullServer.StorageDevices {
			storageTable.AppendRow([]interface{}{
				storage.UUID,
				storage.Title,
				storage.Size,
				storage.Type,
				storage.Address,
			})
		}

		fmt.Println(storageTable.Render())
		fmt.Println()
	}

	// Tags Table (if any)
	if len(fullServer.Tags) > 0 {
		tagsTable := createBoxedTable()
		tagsTable.SetTitle("Tags")
		for _, tag := range fullServer.Tags {
			tagsTable.AppendRow([]interface{}{tag})
		}

		fmt.Println(tagsTable.Render())
		fmt.Println()
	}

	fmt.Println("Press Enter to continue...")
	fmt.Scanln()

	// Return to action menu
	return ls.showActionMenu(server, exec)
}

// executeAction performs the selected action on the server
func (ls *listCommand) executeAction(action ActionItem, server ServerItem, exec commands.Executor) (output.Output, error) {
	switch action.Command {
	case "show":
		// Use our enhanced server details display
		return ls.showEnhancedServerDetails(server, exec)
	case "start":
		startCmd := StartCommand().(*startCommand)
		return startCmd.Execute(exec, server.UUID)
	case "restart":
		restartCmd := RestartCommand().(*restartCommand)
		return restartCmd.Execute(exec, server.UUID)
	case "stop":
		stopCmd := StopCommand().(*stopCommand)
		return stopCmd.Execute(exec, server.UUID)
	case "delete":
		// Confirm deletion
		fmt.Printf("\n⚠️  WARNING: Are you sure you want to delete %s?\n", server.Hostname)
		fmt.Printf("This action cannot be undone. Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return output.OnlyMarshaled{Value: "Deletion cancelled"}, nil
		}

		input = strings.TrimSpace(input)
		if input != "yes" {
			fmt.Printf("\nDeletion cancelled.\n")
			return output.OnlyMarshaled{Value: "Deletion cancelled"}, nil
		}

		deleteCmd := DeleteCommand().(*deleteCommand)
		return deleteCmd.Execute(exec, server.UUID)
	case "back":
		// Return to server selection - fetch fresh server list
		servers, err := exec.All().GetServers(exec.Context())
		if err != nil {
			return nil, err
		}
		return ls.handleInteractiveMode(servers, exec)
	case "exit":
		// Exit cleanly
		fmt.Printf("\nGoodbye!\n")
		return output.OnlyMarshaled{Value: ""}, nil
	default:
		return nil, fmt.Errorf("unknown action: %s", action.Command)
	}
}
