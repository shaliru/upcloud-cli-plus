package server

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands/network"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/format"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/output"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/terminal"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/ui"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/request"
	"github.com/charmbracelet/bubbles/viewport"
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

	// Server state colors (using soothing colors similar to Claude's output)
	stateStartedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("34")). // Softer green
				Bold(true)
	stateStoppedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#E55A5A")). // More reddish, less pink
				Bold(true)
	stateMaintenanceStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("208")). // Orange
				Bold(true)
	stateErrorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")). // Muted gray (like the "+32 lines" text)
			Bold(true)
)

// getStateStyle returns the appropriate lipgloss style for a server state
func getStateStyle(state string) lipgloss.Style {
	switch state {
	case "started":
		return stateStartedStyle
	case "stopped":
		return stateStoppedStyle
	case "maintenance":
		return stateMaintenanceStyle
	case "error":
		return stateErrorStyle
	default:
		return normalStyle
	}
}

// abbreviateState returns a shortened version of server state for better table alignment
func abbreviateState(state string) string {
	switch state {
	case "maintenance":
		return "maint"
	default:
		return state
	}
}

// TUI Models
type viewType int

const (
	serverSelectionView viewType = iota
	loadingView
	serverDetailsView
	createWizardView
	osTemplateSelectionView
)

type detailContentType int

const (
	overviewContent detailContentType = iota
	firewallContent
)

type createWizardStep int

const (
	basicInfoStep createWizardStep = iota
	planCategoryStep
	planSelectionStep
	osTemplateStep
	authenticationStep
	reviewStep
)

type tuiModel struct {
	view           viewType
	servers        []ServerItem
	selected       int
	currentServer  ServerItem
	detailsOptions []string
	currentContent detailContentType
	serverDetails  *upcloud.ServerDetails
	firewallRules  *upcloud.FirewallRules
	viewport       viewport.Model
	contentHeight  int
	exec           commands.Executor
	listCmd        *listCommand
	quitting       bool
	result         output.Output
	err            error
	loadingMsg     string

	// Create wizard state
	createStep       createWizardStep
	createData       createWizardData
	createError      string
	planScrollOffset int    // For scrolling plan selection
	textInputMode    bool   // Whether we're in text input mode
	textInputField   string // Which field is being edited

	// OS template selection state
	osTemplateFilter  string            // Filter text for OS templates
	filteredTemplates []upcloud.Storage // Filtered list based on search
	osScrollOffset    int               // For scrolling OS template selection

	// API data for wizard
	zones        []upcloud.Zone
	plans        []upcloud.Plan
	templates    []upcloud.Storage
	plansGrouped []PlanGroup
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

	p := tea.NewProgram(model, tea.WithInput(os.Stdin), tea.WithOutput(os.Stderr), tea.WithoutCatchPanics())
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("TUI error: %w", err)
	}

	// Clean up terminal state after TUI exits - restore cursor and clear any remaining artifacts
	fmt.Fprint(os.Stderr, "\033[?25h") // Show cursor
	fmt.Fprint(os.Stderr, "\033[0m")   // Reset all attributes
	fmt.Fprint(os.Stderr, "\033[K")    // Clear to end of line

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

// CreateWizardData holds the data being collected in the wizard
type createWizardData struct {
	hostname         string
	title            string
	zone             string
	planCategory     string // Selected plan category (e.g., "General Purpose")
	plan             string
	osTemplate       string
	authMethod       string // "ssh", "password", "email", "sms"
	sshKeys          []string
	passwordDelivery string

	// SSH key management
	discoveredKeys []SSHKeyOption
	selectedKeyIds []int  // indices of selected keys
	manualKey      string // manually entered key
	manualKeyPath  string // manually entered file path
}

// PlanGroup represents a group of server plans
type PlanGroup struct {
	Name        string
	Description string
	Plans       []upcloud.Plan
}

// SSHKeyOption represents an SSH key choice
type SSHKeyOption struct {
	Name     string
	Path     string
	Type     string // "discovered", "manual", "file"
	Selected bool
}

// TUI Methods
func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if m.view == serverDetailsView {
			// Update viewport dimensions when window size changes
			m.setupViewport(msg.Width, msg.Height)
		}
	case loadServerDetailsMsg:
		if msg.err != nil {
			m.err = msg.err
			m.quitting = true
			return m, tea.Quit
		}

		// Successfully loaded server details
		m.serverDetails = msg.details
		m.firewallRules = msg.firewallRules

		// Build navigation options including server actions
		m.detailsOptions = []string{"Server overview"}
		if msg.details.Firewall == "on" {
			m.detailsOptions = append(m.detailsOptions, "Firewall rules")
		}

		// Add server actions based on state
		if m.currentServer.State == "stopped" {
			m.detailsOptions = append(m.detailsOptions, "Start server")
		}
		if m.currentServer.State == "started" {
			m.detailsOptions = append(m.detailsOptions, "Restart server")
			m.detailsOptions = append(m.detailsOptions, "Stop server")
		}
		if m.currentServer.State == "stopped" {
			m.detailsOptions = append(m.detailsOptions, "Delete server")
		}

		// Always add back option
		m.detailsOptions = append(m.detailsOptions, "Back to server list")

		// Set up viewport and show server overview by default
		termWidth, termHeight := terminal.GetTerminalSize()
		m.setupViewport(termWidth, termHeight)
		m.currentContent = overviewContent
		content := m.renderOverviewContent()
		m.viewport.SetContent(content)

		m.view = serverDetailsView
		m.selected = 0
		return m, nil
	case loadServerListMsg:
		if msg.err != nil {
			m.err = msg.err
			m.quitting = true
			return m, tea.Quit
		}

		// Successfully loaded server list
		m.servers = msg.servers
		m.view = serverSelectionView
		m.selected = 0
		return m, nil
	case loadCreateWizardDataMsg:
		if msg.err != nil {
			m.err = msg.err
			m.quitting = true
			return m, tea.Quit
		}

		// Successfully loaded wizard data
		m.zones = msg.zones
		m.plans = msg.plans
		m.templates = msg.templates
		m.plansGrouped = groupPlans(msg.plans)

		// Initialize wizard state
		m.createStep = basicInfoStep
		m.createData = createWizardData{
			hostname:       "",                                       // Empty to force user input
			osTemplate:     "Ubuntu Server 24.04 LTS (Noble Numbat)", // Default
			authMethod:     "ssh",                                    // Default
			discoveredKeys: discoverSSHKeys(),                        // Auto-discover SSH keys
		}
		m.createError = ""
		m.selected = 0

		m.view = createWizardView
		return m, nil
	case createServerMsg:
		if msg.err != nil {
			m.createError = "Server creation failed: " + msg.err.Error()
			m.view = createWizardView
			return m, nil
		}

		// Server created successfully!
		m.result = output.MarshaledWithHumanDetails{
			Value: msg.server,
			Details: []output.DetailRow{
				{Title: "UUID", Value: msg.server.UUID, Colour: ui.DefaultUUUIDColours},
				{Title: "Hostname", Value: msg.server.Hostname},
				{Title: "State", Value: msg.server.State},
			},
		}
		m.quitting = true
		return m, tea.Quit
	case string:
		if msg == "refresh_servers" {
			// Timer expired, refresh the server list
			m.loadingMsg = "Refreshing server list..."
			m.view = loadingView
			return m, m.loadServerListCmd()
		}
	case tea.KeyMsg:
		// Handle text input mode first
		if m.textInputMode {
			switch msg.String() {
			case "enter":
				// Confirm text input
				m.textInputMode = false
				m.textInputField = ""
				return m, nil
			case "esc":
				// Cancel text input
				if m.textInputField == "hostname" {
					m.createData.hostname = "" // Reset to empty
				}
				m.textInputMode = false
				m.textInputField = ""
				return m, nil
			case "backspace":
				// Remove last character
				if m.textInputField == "hostname" && len(m.createData.hostname) > 0 {
					m.createData.hostname = m.createData.hostname[:len(m.createData.hostname)-1]
				}
				return m, nil
			default:
				// Add character to text field
				char := msg.String()
				// Only accept valid hostname characters
				if m.textInputField == "hostname" && len(char) == 1 && isValidHostnameChar(char) {
					m.createData.hostname += char
				}
				return m, nil
			}
		}

		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.view == serverSelectionView {
				if m.selected > 0 {
					m.selected--
				}
			} else if m.view == serverDetailsView {
				// In server details view, always navigate menu options
				if m.selected > 0 {
					m.selected--
				}
			} else if m.view == createWizardView && !m.textInputMode {
				// In create wizard, navigate options based on current step
				if m.createStep == basicInfoStep {
					if m.selected > 0 {
						m.selected--
					}
				} else if m.createStep == planCategoryStep {
					if m.selected > 0 {
						m.selected--
					}
				} else if m.createStep == planSelectionStep {
					categoryPlans := m.getPlansForCategory(m.createData.planCategory)
					if len(categoryPlans) > 0 && m.selected > 0 {
						m.selected--
					}
				} else if m.createStep == osTemplateStep {
					// Navigate OS templates
					if len(m.templates) > 0 && m.selected > 0 {
						m.selected--
						m.updateOSScrollOffset()
					}
				} else if m.createStep == authenticationStep {
					totalAuthOptions := m.getTotalAuthOptions()
					if totalAuthOptions > 0 && m.selected > 0 {
						m.selected--
					}
				} else if m.createStep == reviewStep {
					if m.selected > 0 {
						m.selected--
					}
				}
			} else if m.view == osTemplateSelectionView {
				// Navigate OS templates
				if len(m.filteredTemplates) > 0 && m.selected > 0 {
					m.selected--
					m.updateOSScrollOffset()
				}
			}
		case "down", "j":
			if m.view == serverSelectionView {
				// +1 for "Create new server" option
				if m.selected < len(m.servers) {
					m.selected++
				}
			} else if m.view == serverDetailsView {
				// In server details view, always navigate menu options
				if m.selected < len(m.detailsOptions)-1 {
					m.selected++
				}
			} else if m.view == createWizardView && !m.textInputMode {
				// In create wizard, navigate options based on current step
				if m.createStep == basicInfoStep {
					// Allow selection of hostname (0) and zones (1+)
					maxSelection := 0 // Start with just hostname field
					if m.createData.hostname != "" && len(m.zones) > 0 {
						maxSelection = len(m.zones) // Add zones if hostname is entered
					}
					if m.selected < maxSelection {
						m.selected++
					}
				} else if m.createStep == planCategoryStep {
					// Navigate through available plan categories
					if m.selected < len(m.plansGrouped)-1 {
						m.selected++
					}
				} else if m.createStep == planSelectionStep {
					categoryPlans := m.getPlansForCategory(m.createData.planCategory)
					if len(categoryPlans) > 0 && m.selected < len(categoryPlans)-1 {
						m.selected++
					}
				} else if m.createStep == osTemplateStep {
					// Navigate OS templates
					if len(m.templates) > 0 && m.selected < len(m.templates)-1 {
						m.selected++
						m.updateOSScrollOffset()
					}
				} else if m.createStep == authenticationStep {
					totalAuthOptions := m.getTotalAuthOptions()
					if totalAuthOptions > 0 && m.selected < totalAuthOptions-1 {
						m.selected++
					}
				} else if m.createStep == reviewStep {
					if m.selected < 1 {
						m.selected++
					}
				}
			} else if m.view == osTemplateSelectionView {
				// Navigate OS templates
				if len(m.filteredTemplates) > 0 && m.selected < len(m.filteredTemplates)-1 {
					m.selected++
					m.updateOSScrollOffset()
				}
			}
		case "pgup":
			if m.view == serverDetailsView {
				// Line-by-line scrolling up (instead of page scrolling)
				m.viewport.LineUp(1)
			}
		case "pgdown":
			if m.view == serverDetailsView {
				// Line-by-line scrolling down (instead of page scrolling)
				m.viewport.LineDown(1)
			}
		case "home":
			if m.view == serverDetailsView {
				m.viewport.GotoTop()
			}
		case "end":
			if m.view == serverDetailsView {
				m.viewport.GotoBottom()
			}
		case "r":
			if m.view == serverSelectionView {
				// Manual refresh of server list
				m.loadingMsg = "Refreshing server list..."
				m.view = loadingView
				return m, m.loadServerListCmd()
			}
		case " ": // spacebar
			if m.view == createWizardView && m.createStep == authenticationStep {
				// Toggle SSH key selection
				authOptions := getAuthenticationOptions(m.createData.osTemplate)
				if len(authOptions) > 0 {
					// Calculate which SSH key is selected (if any)
					keyIndex := m.selected - len(authOptions)
					if keyIndex >= 0 && keyIndex < len(m.createData.discoveredKeys) {
						// Toggle the SSH key
						m.createData.discoveredKeys[keyIndex].Selected = !m.createData.discoveredKeys[keyIndex].Selected
						m.createError = "" // Clear any error
					}
				}
			}
		case "enter":
			switch m.view {
			case serverSelectionView:
				if m.selected == 0 {
					// Create new server selected
					m.loadingMsg = "Loading create wizard data..."
					m.view = loadingView
					return m, m.loadCreateWizardDataCmd()
				} else {
					// Server selected (offset by 1 due to create option)
					m.currentServer = m.servers[m.selected-1]
					m.loadingMsg = "Loading server details..."
					m.view = loadingView
					return m, m.loadServerDetailsCmd()
				}
			case serverDetailsView:
				// Handle details navigation options
				return m.handleDetailsNavigation()
			case createWizardView:
				// Handle wizard navigation
				return m.handleWizardNavigation()
			case osTemplateSelectionView:
				// OS template selected
				if len(m.filteredTemplates) > 0 && m.selected < len(m.filteredTemplates) {
					selectedTemplate := m.filteredTemplates[m.selected]
					m.createData.osTemplate = selectedTemplate.Title
					m.createError = ""
					m.view = createWizardView
					m.selected = 0
				}
				return m, nil
			}
		case "esc":
			if m.view == serverDetailsView {
				m.loadingMsg = "Refreshing server list..."
				m.view = loadingView
				return m, m.loadServerListCmd()
			} else if m.view == createWizardView {
				// Cancel wizard and return to server list
				m.loadingMsg = "Refreshing server list..."
				m.view = loadingView
				return m, m.loadServerListCmd()
			} else if m.view == osTemplateSelectionView {
				// Cancel OS template selection and return to wizard
				m.view = createWizardView
				m.selected = 0
				return m, nil
			} else if m.view == loadingView {
				m.view = serverSelectionView
				m.selected = 0
			}
		case "backspace", "delete":
			if m.view == createWizardView && !m.textInputMode {
				// Go to previous step in wizard
				switch m.createStep {
				case planCategoryStep:
					m.createStep = basicInfoStep
					m.selected = 0
				case planSelectionStep:
					m.createStep = planCategoryStep
					m.selected = 0
				case osTemplateStep:
					m.createStep = planSelectionStep
					m.selected = 0
				case authenticationStep:
					m.createStep = osTemplateStep
					m.selected = 0
				case reviewStep:
					m.createStep = authenticationStep
					m.selected = 0
				}
				return m, nil
			}
		}
	}

	return m, cmd
}

// setupViewport initializes or updates the viewport dimensions
func (m *tuiModel) setupViewport(termWidth, termHeight int) {
	if termWidth <= 0 {
		termWidth = 80
	}
	if termHeight <= 0 {
		termHeight = 24
	}

	// Calculate space for fixed elements
	headerHeight := 3                             // "Server Details: ..." + spacing
	navigationHeight := len(m.detailsOptions) + 3 // Navigation options + spacing + help text
	marginHeight := 2                             // Top/bottom margins

	// Available height for scrollable content
	availableHeight := termHeight - headerHeight - navigationHeight - marginHeight
	if availableHeight < 5 {
		availableHeight = 5 // Minimum viewport height
	}

	// Setup or update viewport
	if m.viewport.Width == 0 {
		// First time setup
		m.viewport = viewport.New(termWidth, availableHeight)
	} else {
		// Update existing viewport
		m.viewport.Width = termWidth
		m.viewport.Height = availableHeight
	}
}

func (m tuiModel) View() string {
	if m.quitting {
		return "" // Return empty to avoid any final render
	}

	switch m.view {
	case serverSelectionView:
		return m.renderServerSelection()
	case loadingView:
		return m.renderLoading()
	case serverDetailsView:
		return m.renderServerDetails()
	case createWizardView:
		return m.renderCreateWizard()
	case osTemplateSelectionView:
		return m.renderOSTemplateSelection()
	default:
		return "Unknown view"
	}
}

// loadServerDetailsMsg is a message that contains loaded server details
type loadServerDetailsMsg struct {
	details       *upcloud.ServerDetails
	firewallRules *upcloud.FirewallRules
	err           error
}

// loadServerListMsg is a message that contains loaded server list
type loadServerListMsg struct {
	servers []ServerItem
	err     error
}

// loadServerDetailsCmd loads server details asynchronously
func (m tuiModel) loadServerDetailsCmd() tea.Cmd {
	return func() tea.Msg {
		// Load server details
		details, err := m.exec.All().GetServerDetails(m.exec.Context(), &request.GetServerDetailsRequest{UUID: m.currentServer.UUID})
		if err != nil {
			return loadServerDetailsMsg{err: err}
		}

		// Load firewall rules if firewall is enabled
		var fwRules *upcloud.FirewallRules
		if details.Firewall == "on" {
			rules, fwErr := m.exec.All().GetFirewallRules(m.exec.Context(), &request.GetFirewallRulesRequest{ServerUUID: m.currentServer.UUID})
			if fwErr == nil {
				fwRules = rules
			}
		}

		return loadServerDetailsMsg{
			details:       details,
			firewallRules: fwRules,
			err:           nil,
		}
	}
}

// loadServerListCmd loads server list asynchronously
func (m tuiModel) loadServerListCmd() tea.Cmd {
	return func() tea.Msg {
		// Get servers
		servers, err := m.exec.All().GetServers(m.exec.Context())
		if err != nil {
			return loadServerListMsg{err: err}
		}

		// Convert to ServerItem format (same logic as original)
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
				publicIP := getServerPublicIP(srv.UUID, m.exec)
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

		// Create server items with IP addresses
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

		return loadServerListMsg{
			servers: serverItems,
			err:     nil,
		}
	}
}

// loadCreateWizardDataCmd loads zones, plans, and templates for the wizard
func (m tuiModel) loadCreateWizardDataCmd() tea.Cmd {
	return func() tea.Msg {
		// Load zones
		zones, err := m.exec.All().GetZones(m.exec.Context())
		if err != nil {
			return loadCreateWizardDataMsg{err: fmt.Errorf("failed to load zones: %w", err)}
		}

		// Load plans
		plans, err := m.exec.All().GetPlans(m.exec.Context())
		if err != nil {
			return loadCreateWizardDataMsg{err: fmt.Errorf("failed to load plans: %w", err)}
		}

		// Load OS templates (public storage templates) - make this optional for now
		var templateStorages []upcloud.Storage
		templates, err := m.exec.Storage().GetStorages(m.exec.Context(), &request.GetStoragesRequest{})
		if err != nil {
			// Template loading failed, but don't fail the whole wizard
			// We can still proceed with zones and plans
			templateStorages = []upcloud.Storage{}
		} else {
			// Filter for public templates and exclude K8s templates
			for _, storage := range templates.Storages {
				if storage.Access == upcloud.StorageAccessPublic && storage.Type == upcloud.StorageTypeTemplate {
					// Exclude Kubernetes and GPU templates
					if !isKubernetesTemplate(storage.Title) && !isGPUTemplate(storage.Title) {
						templateStorages = append(templateStorages, storage)
					}
				}
			}

			// Sort templates by priority: Linux distributions first, then Windows
			sortTemplatesByPriority(templateStorages)
		}

		return loadCreateWizardDataMsg{
			zones:     zones.Zones,
			plans:     plans.Plans,
			templates: templateStorages,
			err:       nil,
		}
	}
}

// createServerCmd creates a server using the wizard data
func (m tuiModel) createServerCmd() tea.Cmd {
	return func() tea.Msg {
		// Build the create server request
		req, err := m.buildCreateServerRequest()
		if err != nil {
			return createServerMsg{err: err}
		}

		// Create the server
		server, err := m.exec.All().CreateServer(m.exec.Context(), req)
		if err != nil {
			return createServerMsg{err: err}
		}

		return createServerMsg{
			server: server,
			err:    nil,
		}
	}
}

func (m tuiModel) renderLoading() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("UpCloud CLI Plus"))
	b.WriteString("\n\n")

	// Loading message
	b.WriteString(selectedStyle.Render(m.loadingMsg))
	b.WriteString("\n\n")

	// Help text
	b.WriteString(helpStyle.Render("Please wait..."))

	return b.String()
}

func (m tuiModel) renderServerSelection() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Server Selection"))
	b.WriteString("\n\n")

	// Create new server option
	if m.selected == 0 {
		b.WriteString(selectedStyle.Render("> Create new server"))
	} else {
		b.WriteString(normalStyle.Render("  Create new server"))
	}
	b.WriteString("\n\n")

	// Header (with 3-space indent to match server rows)
	b.WriteString(fmt.Sprintf("   %-38s %-25s %-23s %-9s %-9s %s\n",
		"UUID", "Hostname", "Plan", "Zone", "State", "Public IPv4"))
	b.WriteString(strings.Repeat("─", 130))
	b.WriteString("\n")

	// Server list (offset selection by 1 due to create option)
	for i, server := range m.servers {
		// Build the line with colored state column
		uuid := fmt.Sprintf("%-38s", server.UUID)
		hostname := fmt.Sprintf("%-25s", server.Hostname)
		plan := fmt.Sprintf("%-23s", server.Plan)
		zone := fmt.Sprintf("%-9s", server.Zone)
		stateAbbrev := abbreviateState(server.State)
		state := fmt.Sprintf("%-9s", stateAbbrev)
		publicIP := server.PublicIP

		// Apply state color to the state column (using original state for color lookup)
		stateColored := getStateStyle(server.State).Render(state)

		// Build the complete line
		linePrefix := fmt.Sprintf("%s %s %s %s ", uuid, hostname, plan, zone)
		lineSuffix := fmt.Sprintf(" %s", publicIP)

		if i+1 == m.selected { // +1 because of "Create new server" option
			// For selected row, apply purple background to everything except the colored state
			b.WriteString(selectedStyle.Render("> " + linePrefix))
			b.WriteString(stateColored)
			b.WriteString(selectedStyle.Render(lineSuffix))
		} else {
			b.WriteString(normalStyle.Render("  " + linePrefix))
			b.WriteString(stateColored)
			b.WriteString(normalStyle.Render(lineSuffix))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate • enter: select • r: refresh • q/ctrl+c: quit"))
	return b.String()
}

func (m tuiModel) renderServerDetails() string {
	var b strings.Builder

	// Header (fixed at top)
	header := headerStyle.Render(fmt.Sprintf("Server Details: %s", m.currentServer.Hostname))
	b.WriteString(header)
	b.WriteString("\n\n")

	// Render viewport (scrollable content area)
	b.WriteString(m.viewport.View())
	b.WriteString("\n")

	// Navigation options (fixed at bottom)
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

	// Show scroll indicators and help
	scrollInfo := ""
	if !m.viewport.AtTop() && !m.viewport.AtBottom() {
		scrollInfo = "▲▼ "
	} else if !m.viewport.AtTop() {
		scrollInfo = "▲ "
	} else if !m.viewport.AtBottom() {
		scrollInfo = "▼ "
	}

	helpText := fmt.Sprintf("%s↑/↓: navigate • fn+↑/↓: scroll content • enter: select • esc: back", scrollInfo)
	b.WriteString(helpStyle.Render(helpText))

	return b.String()
}

// renderCreateWizard renders the create server wizard
func (m tuiModel) renderCreateWizard() string {
	var b strings.Builder

	// Header with breadcrumb
	stepNames := []string{"Basic Info", "Plan Category", "Plan Selection", "OS Template", "Authentication", "Review"}
	breadcrumb := fmt.Sprintf("Server List > Create Server > Step %d: %s", int(m.createStep)+1, stepNames[m.createStep])
	b.WriteString(headerStyle.Render(breadcrumb))
	b.WriteString("\n\n")

	// Show error if any
	if m.createError != "" {
		b.WriteString(ui.DefaultErrorColours.Sprint("Error: " + m.createError))
		b.WriteString("\n\n")
	}

	// Render current step
	switch m.createStep {
	case basicInfoStep:
		b.WriteString(m.renderBasicInfoStep())
	case planCategoryStep:
		b.WriteString(m.renderPlanCategoryStep())
	case planSelectionStep:
		b.WriteString(m.renderPlanSelectionStep())
	case osTemplateStep:
		b.WriteString(m.renderOSTemplateStep())
	case authenticationStep:
		b.WriteString(m.renderAuthenticationStep())
	case reviewStep:
		b.WriteString(m.renderReviewStep())
	}

	b.WriteString("\n")

	// Status bar with separator line
	b.WriteString(strings.Repeat("─", 64) + "\n")
	b.WriteString("Current: " + m.renderWizardStatusBar() + "\n")

	b.WriteString(helpStyle.Render("↑/↓: navigate • enter: select/next • esc: cancel • backspace: previous step"))

	return b.String()
}

// renderBasicInfoStep renders the first step of the wizard
func (m tuiModel) renderBasicInfoStep() string {
	var b strings.Builder

	b.WriteString("Enter basic server information:\n\n")

	// Hostname field with text input support
	if m.textInputMode && m.textInputField == "hostname" {
		b.WriteString("Hostname: ")
		hostnameDisplay := m.createData.hostname
		if hostnameDisplay == "" {
			hostnameDisplay = ""
		}
		b.WriteString(selectedStyle.Render(hostnameDisplay + "│")) // Show cursor
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("Type hostname and press Enter to confirm, Esc to cancel"))
		b.WriteString("\n")
	} else {
		hostnameDisplay := m.createData.hostname
		if hostnameDisplay == "" {
			hostnameDisplay = "[Press Enter to enter hostname]"
		}
		if m.selected == 0 { // Hostname field selected
			b.WriteString(fmt.Sprintf("Hostname: %s\n", selectedStyle.Render("> "+hostnameDisplay)))
		} else {
			b.WriteString(fmt.Sprintf("Hostname: %s\n", normalStyle.Render("  "+hostnameDisplay)))
		}
	}

	// Title field (optional)
	titleDisplay := m.createData.title
	if titleDisplay == "" {
		titleDisplay = "[auto-generated from hostname]"
	}
	b.WriteString(fmt.Sprintf("Title: %s\n", normalStyle.Render("  "+titleDisplay)))

	// Zone selection (only if hostname is entered)
	if m.createData.hostname != "" && !m.textInputMode {
		b.WriteString("\nSelect Zone:\n")
		if len(m.zones) == 0 {
			b.WriteString("Loading zones...")
		} else {
			for i, zone := range m.zones {
				// Offset selection by 1 to account for hostname field
				if i == m.selected-1 && m.selected > 0 {
					b.WriteString(selectedStyle.Render("> " + zone.ID))
				} else {
					b.WriteString(normalStyle.Render("  " + zone.ID))
				}
				b.WriteString("\n")
			}
		}
	} else if m.createData.hostname == "" && !m.textInputMode {
		b.WriteString("\n" + helpStyle.Render("Enter a hostname to continue"))
	}

	return b.String()
}

// renderPlanCategoryStep renders the plan category selection step
func (m tuiModel) renderPlanCategoryStep() string {
	var b strings.Builder

	b.WriteString("Select a server plan category:\n\n")

	// Get plan categories dynamically from grouped plans
	var categories []struct {
		name  string
		count int
	}
	for _, group := range m.plansGrouped {
		categories = append(categories, struct {
			name  string
			count int
		}{
			name:  group.Name,
			count: len(group.Plans),
		})
	}

	// Render categories
	for i, category := range categories {
		if i == m.selected {
			b.WriteString(selectedStyle.Render(fmt.Sprintf("> %s (%d plans)", category.name, category.count)))
		} else {
			b.WriteString(normalStyle.Render(fmt.Sprintf("  %s (%d plans)", category.name, category.count)))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// renderPlanSelectionStep renders the specific plan selection step
func (m tuiModel) renderPlanSelectionStep() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Select a %s plan:\n\n", m.createData.planCategory))

	// Table header
	b.WriteString(fmt.Sprintf("   %-18s │ %-7s │ %-6s │ %-8s │ %-8s │ %s\n",
		"Name", "Cores", "Memory", "Storage", "Tier", "Transfer"))
	b.WriteString("   " + strings.Repeat("─", 75) + "\n")

	// Get plans for selected category
	categoryPlans := m.getPlansForCategory(m.createData.planCategory)

	// Render plans
	for i, plan := range categoryPlans {
		transferTB := formatTransfer(plan.PublicTrafficOut)

		planLine := fmt.Sprintf("%-18s │ %7s │ %6s │ %8s │ %-8s │ %s",
			plan.Name,
			fmt.Sprintf("%d", plan.CoreNumber),
			fmt.Sprintf("%d GB", plan.MemoryAmount/1024),
			fmt.Sprintf("%d GB", plan.StorageSize),
			plan.StorageTier,
			transferTB)

		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + planLine))
		} else {
			b.WriteString(normalStyle.Render("  " + planLine))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// renderOSTemplateStep renders the OS template selection step
func (m tuiModel) renderOSTemplateStep() string {
	var b strings.Builder

	b.WriteString("Select an operating system template:\n\n")

	// Table header
	b.WriteString(fmt.Sprintf("   %-50s %-12s %-8s %s\n",
		"Template Name", "Size", "Access", "Type"))
	b.WriteString("   " + strings.Repeat("─", 85) + "\n")

	// Calculate terminal height for scrolling
	termHeight := terminal.GetTerminalHeight()
	if termHeight <= 0 {
		termHeight = 24 // Default fallback
	}

	// Reserve space for header, breadcrumb, step title, table header, help text
	availableLines := termHeight - 10
	if availableLines < 5 {
		availableLines = 5
	}

	// Apply scrolling to templates
	startIdx := m.osScrollOffset
	endIdx := startIdx + availableLines
	if endIdx > len(m.templates) {
		endIdx = len(m.templates)
	}

	// Render visible templates
	for i := startIdx; i < endIdx; i++ {
		template := m.templates[i]

		// Truncate long template names
		templateName := template.Title
		if len(templateName) > 50 {
			templateName = templateName[:47] + "..."
		}

		// Format size in GB
		sizeGB := fmt.Sprintf("%d GB", template.Size)

		templateLine := fmt.Sprintf("%-50s %-12s %-8s %s",
			templateName,
			sizeGB,
			string(template.Access),
			string(template.Type))

		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + templateLine))
		} else {
			b.WriteString(normalStyle.Render("  " + templateLine))
		}
		b.WriteString("\n")
	}

	// Show scroll indicators
	if startIdx > 0 {
		b.WriteString(helpStyle.Render("   ↑ More templates above\n"))
	}
	if endIdx < len(m.templates) {
		b.WriteString(helpStyle.Render("   ↓ More templates below\n"))
	}

	return b.String()
}

// renderPlanOSStep renders the plan and OS selection step
func (m tuiModel) renderPlanOSStep() string {
	var b strings.Builder

	b.WriteString("Select server plan and operating system:\n\n")

	// Plan selection
	b.WriteString("Server Plans:\n")
	if len(m.plansGrouped) == 0 {
		b.WriteString("Loading plans...")
	} else {
		b.WriteString(m.renderPlanSelectionSimple())
	}

	b.WriteString("\n\nOS Template:\n")
	// Show current OS selection
	osDisplay := m.createData.osTemplate
	if osDisplay == "" {
		osDisplay = "Ubuntu Server 24.04 LTS (Noble Numbat)" // Default
	}
	b.WriteString(fmt.Sprintf("Selected: %s\n", selectedStyle.Render(osDisplay)))
	b.WriteString("Press 'o' to change OS template\n")

	return b.String()
}

// renderPlanSelection renders the grouped plan selection (simplified version)
func (m tuiModel) renderPlanSelection() string {
	var b strings.Builder

	// Calculate available space for plans
	termHeight := terminal.GetTerminalHeight()
	if termHeight <= 0 {
		termHeight = 24 // Default fallback
	}

	// Reserve space for header, breadcrumb, step title, OS section, help text
	// Header(1) + empty(1) + step title(2) + table header(2) + OS section(4) + help(2) = 12 lines
	availableLines := termHeight - 12
	if availableLines < 5 {
		availableLines = 5 // Minimum to show at least a few plans
	}

	// Table header (only show once at the top)
	b.WriteString(fmt.Sprintf("\n   %-18s │ %-7s │ %-6s │ %-8s │ %-8s │ %s\n",
		"Name", "Cores", "Memory", "Storage", "Tier", "Transfer"))
	b.WriteString("   " + strings.Repeat("─", 75) + "\n")

	// Build flat list of all plans with group headers for easy indexing
	type planItem struct {
		plan      *upcloud.Plan
		groupName string
		isHeader  bool
	}

	var allItems []planItem
	for _, group := range m.plansGrouped {
		// Add group header
		allItems = append(allItems, planItem{
			groupName: group.Name,
			isHeader:  true,
		})

		// Add plans in group
		for i := range group.Plans {
			allItems = append(allItems, planItem{
				plan:      &group.Plans[i],
				groupName: group.Name,
				isHeader:  false,
			})
		}
	}

	// Calculate scroll window using pre-calculated offset
	totalItems := len(allItems)
	startIdx := m.planScrollOffset
	endIdx := startIdx + availableLines
	if endIdx > totalItems {
		endIdx = totalItems
	}
	if startIdx >= totalItems {
		startIdx = totalItems - availableLines
		if startIdx < 0 {
			startIdx = 0
		}
		endIdx = totalItems
	}

	// Render visible items
	for i := startIdx; i < endIdx; i++ {
		item := allItems[i]

		if item.isHeader {
			// Group header
			b.WriteString(fmt.Sprintf("\n%s\n", ui.DefaultHeaderColours.Sprint(item.groupName)))
		} else {
			// Plan item
			plan := item.plan
			transferTB := formatTransfer(plan.PublicTrafficOut)

			planLine := fmt.Sprintf("%-18s │ %7s │ %6s │ %8s │ %-8s │ %s",
				plan.Name,
				fmt.Sprintf("%d", plan.CoreNumber),
				fmt.Sprintf("%d GB", plan.MemoryAmount/1024),
				fmt.Sprintf("%d GB", plan.StorageSize),
				plan.StorageTier,
				transferTB)

			// Check if this plan is selected by converting index
			if m.isCurrentPlanSelected(plan) {
				b.WriteString(selectedStyle.Render("> " + planLine))
			} else {
				b.WriteString(normalStyle.Render("  " + planLine))
			}
			b.WriteString("\n")
		}
	}

	// Show scroll indicators
	if startIdx > 0 {
		b.WriteString(helpStyle.Render("   ↑ More plans above\n"))
	}
	if endIdx < totalItems {
		b.WriteString(helpStyle.Render("   ↓ More plans below\n"))
	}

	return b.String()
}

// renderPlanSelectionSimple renders plans without complex scrolling
func (m tuiModel) renderPlanSelectionSimple() string {
	var b strings.Builder

	// Table header
	b.WriteString(fmt.Sprintf("\n   %-18s │ %-7s │ %-6s │ %-8s │ %-8s │ %s\n",
		"Name", "Cores", "Memory", "Storage", "Tier", "Transfer"))
	b.WriteString("   " + strings.Repeat("─", 75) + "\n")

	// Simple rendering: show all plans with correct selection
	planIndex := 0
	for _, group := range m.plansGrouped {
		// Group header
		b.WriteString(fmt.Sprintf("\n%s\n", ui.DefaultHeaderColours.Sprint(group.Name)))

		// Plans in this group
		for _, plan := range group.Plans {
			// Format transfer from GiB to TB
			transferTB := formatTransfer(plan.PublicTrafficOut)

			// Build plan display line
			planLine := fmt.Sprintf("%-18s │ %7s │ %6s │ %8s │ %-8s │ %s",
				plan.Name,
				fmt.Sprintf("%d", plan.CoreNumber),
				fmt.Sprintf("%d GB", plan.MemoryAmount/1024),
				fmt.Sprintf("%d GB", plan.StorageSize),
				plan.StorageTier,
				transferTB)

			if planIndex == m.selected {
				b.WriteString(selectedStyle.Render("> " + planLine))
			} else {
				b.WriteString(normalStyle.Render("  " + planLine))
			}
			b.WriteString("\n")
			planIndex++
		}
	}

	return b.String()
}

// getPlansForCategory returns plans for a specific category
func (m tuiModel) getPlansForCategory(categoryName string) []upcloud.Plan {
	for _, group := range m.plansGrouped {
		if group.Name == categoryName {
			return group.Plans
		}
	}
	return []upcloud.Plan{}
}

// renderWizardStatusBar generates the current status of wizard selections
func (m tuiModel) renderWizardStatusBar() string {
	var parts []string

	// Hostname
	if m.createData.hostname != "" {
		parts = append(parts, m.createData.hostname)
	} else {
		parts = append(parts, "[hostname]")
	}

	// Zone
	if m.createData.zone != "" {
		parts = append(parts, m.createData.zone)
	} else {
		parts = append(parts, "[zone]")
	}

	// Plan Category
	if m.createData.planCategory != "" {
		parts = append(parts, m.createData.planCategory)
	} else if m.createStep == planCategoryStep {
		parts = append(parts, "[selecting category...]")
	} else {
		parts = append(parts, "[category]")
	}

	// Specific Plan
	if m.createData.plan != "" {
		parts = append(parts, m.createData.plan)
	} else if m.createStep == planSelectionStep {
		parts = append(parts, "[selecting plan...]")
	} else {
		parts = append(parts, "[plan]")
	}

	// OS Template
	if m.createData.osTemplate != "" {
		// Shorten OS name for status bar
		osShort := strings.ReplaceAll(m.createData.osTemplate, "Server ", "")
		osShort = strings.ReplaceAll(osShort, " LTS", "")
		osShort = strings.ReplaceAll(osShort, " (Noble Numbat)", "")
		parts = append(parts, osShort)
	} else {
		parts = append(parts, "Ubuntu 24.04")
	}

	return strings.Join(parts, " • ")
}

// formatTransfer converts GiB to TB for display
func formatTransfer(gib int) string {
	tb := float64(gib) / 1024.0
	if tb < 1.0 {
		return fmt.Sprintf("%.1f TB", tb)
	}
	return fmt.Sprintf("%.0f TB", tb)
}

// getSelectedPlanIndex returns the absolute index of the selected plan across all groups
func (m tuiModel) getSelectedPlanIndex() int {
	currentIndex := 0
	for _, group := range m.plansGrouped {
		// Count group header
		if currentIndex == m.selected {
			return currentIndex
		}
		currentIndex++

		// Count plans in group
		for range group.Plans {
			if currentIndex == m.selected {
				return currentIndex
			}
			currentIndex++
		}
	}
	return 0
}

// isCurrentPlanSelected checks if the given plan is currently selected
func (m tuiModel) isCurrentPlanSelected(targetPlan *upcloud.Plan) bool {
	currentIndex := 0
	for _, group := range m.plansGrouped {
		// Skip group header
		currentIndex++

		// Check plans in group
		for i := range group.Plans {
			if currentIndex == m.selected && &group.Plans[i] == targetPlan {
				return true
			}
			currentIndex++
		}
	}
	return false
}

// updatePlanScrollOffset updates the scroll offset to keep the selected plan visible
func (m *tuiModel) updatePlanScrollOffset() {
	termHeight := terminal.GetTerminalHeight()
	if termHeight <= 0 {
		termHeight = 24
	}

	availableLines := termHeight - 10 // Reserve space for headers and UI
	if availableLines < 5 {
		availableLines = 5
	}

	selectedIndex := m.getSelectedPlanIndex()

	// Adjust scroll offset to keep selected item visible
	if selectedIndex < m.planScrollOffset {
		m.planScrollOffset = selectedIndex
	} else if selectedIndex >= m.planScrollOffset+availableLines {
		m.planScrollOffset = selectedIndex - availableLines + 1
		if m.planScrollOffset < 0 {
			m.planScrollOffset = 0
		}
	}
}

// isValidHostnameChar checks if a character is valid for hostnames
func isValidHostnameChar(char string) bool {
	if len(char) != 1 {
		return false
	}
	c := char[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
}

// getTotalPlanCount returns the total number of plans across all groups
func (m tuiModel) getTotalPlanCount() int {
	total := 0
	for _, group := range m.plansGrouped {
		total += len(group.Plans)
	}
	return total
}

// getSelectedPlan returns the currently selected plan based on m.selected index
func (m tuiModel) getSelectedPlan() *upcloud.Plan {
	planIndex := 0
	for _, group := range m.plansGrouped {
		for _, plan := range group.Plans {
			if planIndex == m.selected {
				return &plan
			}
			planIndex++
		}
	}
	return nil
}

// discoverSSHKeys finds SSH public keys in the user's ~/.ssh directory
func discoverSSHKeys() []SSHKeyOption {
	var keys []SSHKeyOption

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return keys
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	// Common SSH public key files
	commonKeys := []string{"id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"}

	for _, keyFile := range commonKeys {
		keyPath := filepath.Join(sshDir, keyFile)
		if _, err := os.Stat(keyPath); err == nil {
			// File exists, read first few characters to verify it's a public key
			if isValidSSHPublicKey(keyPath) {
				keys = append(keys, SSHKeyOption{
					Name:     keyFile,
					Path:     keyPath,
					Type:     "discovered",
					Selected: false,
				})
			}
		}
	}

	return keys
}

// isValidSSHPublicKey checks if a file appears to be an SSH public key
func isValidSSHPublicKey(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first line to check format
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// SSH public keys start with ssh-rsa, ssh-ed25519, ssh-ecdsa, etc.
		return strings.HasPrefix(line, "ssh-") && len(line) > 20
	}

	return false
}

// getAuthenticationOptions returns available auth methods based on selected OS
func getAuthenticationOptions(osTemplate string) []string {
	// OS templates that support password delivery
	passwordSupportedOS := []string{
		"Ubuntu Server 20.04 LTS (Focal Fossa)",
		"Debian GNU/Linux 11 (Bullseye)",
		"CentOS Stream 9",
		"AlmaLinux 8",
		"Rocky Linux 8",
	}

	options := []string{"SSH Keys"}

	// Check if password delivery is supported
	for _, supportedOS := range passwordSupportedOS {
		if strings.Contains(osTemplate, supportedOS) {
			options = append(options, "Email Delivery", "SMS Delivery")
			break
		}
	}

	// Windows servers support password delivery
	if strings.Contains(strings.ToLower(osTemplate), "windows") {
		options = append(options, "Email Delivery", "SMS Delivery")
	}

	return options
}

// getTotalAuthOptions returns the total number of selectable items in auth step
func (m tuiModel) getTotalAuthOptions() int {
	authOptions := getAuthenticationOptions(m.createData.osTemplate)
	total := len(authOptions)

	// If SSH Keys method is available (it's always the first option), add SSH key options
	if len(authOptions) > 0 {
		// Add discovered keys
		total += len(m.createData.discoveredKeys)
		// Add manual options (paste SSH key, specify file path)
		total += 2
	}

	return total
}

// renderAuthenticationStep renders the authentication step
func (m tuiModel) renderAuthenticationStep() string {
	var b strings.Builder

	b.WriteString("Configure authentication:\n\n")

	// Get available authentication options based on selected OS
	authOptions := getAuthenticationOptions(m.createData.osTemplate)
	currentIndex := 0

	// Show authentication method selection
	b.WriteString("Authentication Method:\n")
	for _, option := range authOptions {
		if currentIndex == m.selected {
			b.WriteString(selectedStyle.Render("> " + option))
		} else {
			b.WriteString(normalStyle.Render("  " + option))
		}
		b.WriteString("\n")
		currentIndex++
	}

	// Show SSH key options (SSH Keys is always available)
	if len(authOptions) > 0 {
		b.WriteString("\nSSH Key Selection:\n")

		// Show discovered keys
		if len(m.createData.discoveredKeys) > 0 {
			b.WriteString("\nDiscovered Keys:\n")
			for _, key := range m.createData.discoveredKeys {
				checkbox := "☐"
				if key.Selected {
					checkbox = "☑"
				}

				if currentIndex == m.selected {
					b.WriteString(selectedStyle.Render(fmt.Sprintf("> %s %s (%s)", checkbox, key.Name, key.Path)))
				} else {
					b.WriteString(normalStyle.Render(fmt.Sprintf("  %s %s (%s)", checkbox, key.Name, key.Path)))
				}
				b.WriteString("\n")
				currentIndex++
			}
		}

		// Show manual options
		b.WriteString("\nManual Options:\n")

		// Paste SSH key option
		if currentIndex == m.selected {
			b.WriteString(selectedStyle.Render("> [ ] Paste SSH key content"))
		} else {
			b.WriteString(normalStyle.Render("  [ ] Paste SSH key content"))
		}
		b.WriteString("\n")
		currentIndex++

		// File path option
		if currentIndex == m.selected {
			b.WriteString(selectedStyle.Render("> [ ] Specify file path"))
		} else {
			b.WriteString(normalStyle.Render("  [ ] Specify file path"))
		}
		b.WriteString("\n")

		b.WriteString("\nPress 'space' to toggle key selection\n")
	}

	return b.String()
}

// renderReviewStep renders the final review step
func (m tuiModel) renderReviewStep() string {
	var b strings.Builder

	b.WriteString("Review your server configuration:\n\n")

	// Basic Information
	b.WriteString(ui.DefaultHeaderColours.Sprint("Basic Information:") + "\n")
	b.WriteString(fmt.Sprintf("  Hostname: %s\n", m.createData.hostname))
	b.WriteString(fmt.Sprintf("  Title: %s\n", m.getDisplayTitle()))
	b.WriteString(fmt.Sprintf("  Zone: %s\n", m.createData.zone))

	// Plan Information
	b.WriteString("\n" + ui.DefaultHeaderColours.Sprint("Server Plan:") + "\n")
	b.WriteString(fmt.Sprintf("  Plan: %s\n", m.createData.plan))

	// OS Information
	b.WriteString("\n" + ui.DefaultHeaderColours.Sprint("Operating System:") + "\n")
	b.WriteString(fmt.Sprintf("  Template: %s\n", m.createData.osTemplate))

	// Authentication Information
	b.WriteString("\n" + ui.DefaultHeaderColours.Sprint("Authentication:") + "\n")
	switch m.createData.authMethod {
	case "ssh":
		b.WriteString("  Method: SSH Keys\n")
		if len(m.createData.discoveredKeys) > 0 {
			keyCount := 0
			for _, key := range m.createData.discoveredKeys {
				if key.Selected {
					keyCount++
				}
			}
			b.WriteString(fmt.Sprintf("  SSH Keys: %d keys selected\n", keyCount))
		} else {
			b.WriteString("  SSH Keys: Manual key entry\n")
		}
	case "email":
		b.WriteString("  Method: Email Delivery\n")
	case "sms":
		b.WriteString("  Method: SMS Delivery\n")
	}

	b.WriteString("\n")
	if m.validateConfiguration() {
		b.WriteString(selectedStyle.Render("> Create Server"))
		b.WriteString("\n")
		b.WriteString(normalStyle.Render("  Back to previous step"))
	} else {
		b.WriteString(ui.DefaultErrorColours.Sprint("⚠ Configuration incomplete"))
		b.WriteString("\n")
		b.WriteString(normalStyle.Render("  Back to previous step"))
	}

	return b.String()
}

// getDisplayTitle returns the title or auto-generates from hostname
func (m tuiModel) getDisplayTitle() string {
	if m.createData.title != "" {
		return m.createData.title
	}
	if m.createData.hostname != "" {
		return m.createData.hostname
	}
	return "[Not set]"
}

// validateConfiguration checks if all required fields are set
func (m tuiModel) validateConfiguration() bool {
	if m.createData.hostname == "" {
		return false
	}
	if m.createData.zone == "" {
		return false
	}
	if m.createData.plan == "" {
		return false
	}
	if m.createData.authMethod == "ssh" {
		// Check if at least one SSH key is selected or manual key is provided
		hasSelectedKey := false
		for _, key := range m.createData.discoveredKeys {
			if key.Selected {
				hasSelectedKey = true
				break
			}
		}
		if !hasSelectedKey && m.createData.manualKey == "" && m.createData.manualKeyPath == "" {
			return false
		}
	}
	return true
}

// buildCreateServerRequest converts wizard data into a CreateServerRequest
func (m tuiModel) buildCreateServerRequest() (*request.CreateServerRequest, error) {
	req := &request.CreateServerRequest{
		Hostname:         m.createData.hostname,
		Title:            m.getDisplayTitle(),
		Zone:             m.createData.zone,
		Plan:             m.createData.plan,
		VideoModel:       "vga",
		TimeZone:         "UTC",
		Firewall:         "off", // Default to off
		Metadata:         upcloud.False,
		PasswordDelivery: request.PasswordDeliveryNone,
	}

	// Find the selected OS template
	osTemplate, err := m.findOSTemplate(m.createData.osTemplate)
	if err != nil {
		return nil, fmt.Errorf("OS template not found: %w", err)
	}

	// Get plan details for storage size
	selectedPlan := m.getSelectedPlan()
	if selectedPlan == nil {
		return nil, fmt.Errorf("selected plan not found")
	}

	// Create OS storage device
	req.StorageDevices = append(req.StorageDevices, request.CreateServerStorageDevice{
		Action:  "clone",
		Address: "virtio",
		Storage: osTemplate.UUID,
		Title:   fmt.Sprintf("%s-OS", m.createData.hostname),
		Size:    selectedPlan.StorageSize,
		Type:    upcloud.StorageTypeDisk,
	})

	// Handle authentication
	if err := m.configureAuthentication(req); err != nil {
		return nil, fmt.Errorf("failed to configure authentication: %w", err)
	}

	return req, nil
}

// findOSTemplate finds the OS template by name
func (m tuiModel) findOSTemplate(templateName string) (*upcloud.Storage, error) {
	for _, template := range m.templates {
		if template.Title == templateName {
			return &template, nil
		}
	}
	// Fallback: use default Ubuntu template UUID if not found in loaded templates
	defaultTemplate := &upcloud.Storage{
		UUID:  "01000000-0000-4000-8000-000020050100", // Ubuntu 24.04 LTS UUID
		Title: templateName,
	}
	return defaultTemplate, nil
}

// configureAuthentication sets up authentication for the server request
func (m tuiModel) configureAuthentication(req *request.CreateServerRequest) error {
	if req.LoginUser == nil {
		req.LoginUser = &request.LoginUser{}
	}

	switch m.createData.authMethod {
	case "ssh":
		req.LoginUser.CreatePassword = "no"

		// Collect SSH keys
		var sshKeys []string

		// Add selected discovered keys
		for i, key := range m.createData.discoveredKeys {
			if key.Selected {
				// Read the SSH key content
				content, err := os.ReadFile(key.Path)
				if err != nil {
					return fmt.Errorf("failed to read SSH key %s: %w", key.Path, err)
				}
				sshKeys = append(sshKeys, strings.TrimSpace(string(content)))
			}
			_ = i // avoid unused variable
		}

		// Add manual key if provided
		if m.createData.manualKey != "" {
			sshKeys = append(sshKeys, m.createData.manualKey)
		}

		// Read manual key file if provided
		if m.createData.manualKeyPath != "" {
			content, err := os.ReadFile(m.createData.manualKeyPath)
			if err != nil {
				return fmt.Errorf("failed to read manual SSH key file %s: %w", m.createData.manualKeyPath, err)
			}
			sshKeys = append(sshKeys, strings.TrimSpace(string(content)))
		}

		if len(sshKeys) == 0 {
			return fmt.Errorf("no SSH keys provided")
		}

		req.LoginUser.SSHKeys = sshKeys

	case "email":
		req.LoginUser.CreatePassword = "yes"
		req.PasswordDelivery = request.PasswordDeliveryEmail

	case "sms":
		req.LoginUser.CreatePassword = "yes"
		req.PasswordDelivery = request.PasswordDeliverySMS
	}

	return nil
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
		// Update viewport content
		content := m.renderOverviewContent()
		m.viewport.SetContent(content)
		m.viewport.GotoTop()
		return m, nil
	case "Firewall rules":
		m.currentContent = firewallContent
		// Update viewport content
		content := m.renderFirewallContent()
		m.viewport.SetContent(content)
		m.viewport.GotoTop()
		return m, nil
	case "Start server":
		return m.executeServerAction("start")
	case "Restart server":
		return m.executeServerAction("restart")
	case "Stop server":
		return m.executeServerAction("stop")
	case "Delete server":
		return m.executeServerAction("delete")
	case "Back to server list":
		m.loadingMsg = "Refreshing server list..."
		m.view = loadingView
		return m, m.loadServerListCmd()
	default:
		return m, nil
	}
}

func (m tuiModel) handleWizardNavigation() (tea.Model, tea.Cmd) {
	switch m.createStep {
	case basicInfoStep:
		if m.selected == 0 && m.createData.hostname == "" {
			// Enter text input mode for hostname
			m.textInputMode = true
			m.textInputField = "hostname"
			return m, nil
		} else if m.createData.hostname != "" && m.selected > 0 && len(m.zones) > 0 && m.selected-1 < len(m.zones) {
			// Zone selected (offset by 1 due to hostname field)
			m.createData.zone = m.zones[m.selected-1].ID
			// Move to plan category step
			m.createStep = planCategoryStep
			m.selected = 0
		}
		return m, nil
	case planCategoryStep:
		// Select plan category dynamically
		if m.selected < len(m.plansGrouped) {
			m.createData.planCategory = m.plansGrouped[m.selected].Name
			// Move to plan selection step
			m.createStep = planSelectionStep
			m.selected = 0
		}
		return m, nil
	case planSelectionStep:
		// Select specific plan within category
		categoryPlans := m.getPlansForCategory(m.createData.planCategory)
		if m.selected < len(categoryPlans) {
			selectedPlan := categoryPlans[m.selected]
			m.createData.plan = selectedPlan.Name
			// Move to OS template step
			m.createStep = osTemplateStep
			m.selected = 0
		}
		return m, nil
	case osTemplateStep:
		// Select OS template
		if m.selected < len(m.templates) {
			selectedTemplate := m.templates[m.selected]
			m.createData.osTemplate = selectedTemplate.Title
			// Move to authentication step
			m.createStep = authenticationStep
			m.selected = 0
		}
		return m, nil
	case authenticationStep:
		// In authentication step, handle auth method selection
		authOptions := getAuthenticationOptions(m.createData.osTemplate)
		if len(authOptions) > 0 && m.selected < len(authOptions) {
			selectedAuth := authOptions[m.selected]
			switch selectedAuth {
			case "SSH Keys":
				m.createData.authMethod = "ssh"
			case "Email Delivery":
				m.createData.authMethod = "email"
				m.createData.passwordDelivery = "email"
			case "SMS Delivery":
				m.createData.authMethod = "sms"
				m.createData.passwordDelivery = "sms"
			}
			// Move to review step
			m.createStep = reviewStep
			m.selected = 0
		}
		return m, nil
	case reviewStep:
		// In review step, handle create server action
		if m.selected == 0 && m.validateConfiguration() {
			// Create server
			m.loadingMsg = "Creating server..."
			m.view = loadingView
			return m, m.createServerCmd()
		} else if m.selected == 1 {
			// Back to previous step
			m.createStep = authenticationStep
			m.selected = 0
		}
		return m, nil
	default:
		return m, nil
	}
}

func (m tuiModel) executeServerAction(action string) (tea.Model, tea.Cmd) {
	// Perform the server action
	switch action {
	case "start":
		// Start the server asynchronously (non-blocking) without progress output
		go func() {
			svc := m.exec.Server()
			svc.StartServer(m.exec.Context(), &request.StartServerRequest{
				UUID: m.currentServer.UUID,
			})
		}()

		// Show temporary status message
		m.loadingMsg = "Starting server..."
		m.view = loadingView

		// Set a timer to return to server list after 3 seconds
		return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg {
			return "refresh_servers" // Custom message to trigger server list refresh
		})
	case "restart":
		// Restart the server asynchronously (non-blocking) without progress output
		go func() {
			svc := m.exec.Server()
			svc.RestartServer(m.exec.Context(), &request.RestartServerRequest{
				UUID: m.currentServer.UUID,
			})
		}()

		// Show temporary status message
		m.loadingMsg = "Restarting server..."
		m.view = loadingView

		// Set a timer to return to server list after 3 seconds
		return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg {
			return "refresh_servers" // Custom message to trigger server list refresh
		})
	case "stop":
		// Stop the server asynchronously (non-blocking) without progress output
		go func() {
			svc := m.exec.Server()
			svc.StopServer(m.exec.Context(), &request.StopServerRequest{
				UUID: m.currentServer.UUID,
			})
		}()

		// Show temporary status message
		m.loadingMsg = "Stopping server..."
		m.view = loadingView

		// Set a timer to return to server list after 3 seconds
		return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg {
			return "refresh_servers" // Custom message to trigger server list refresh
		})
	case "delete":
		// For delete, we need to confirm and then exit to server list
		deleteCmd := DeleteCommand().(*deleteCommand)
		_, err := deleteCmd.Execute(m.exec, m.currentServer.UUID)
		if err != nil {
			m.err = err
			m.quitting = true
			return m, tea.Quit
		}
		// Go back to server list after deletion with refresh
		m.loadingMsg = "Refreshing server list..."
		m.view = loadingView
		return m, m.loadServerListCmd()
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
	fmt.Printf("\nWARNING: Are you sure you want to delete %s?\n", serverName)
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

// groupPlans organizes plans by type, excluding GPU and Cloud Native plans
func groupPlans(plans []upcloud.Plan) []PlanGroup {
	groups := []PlanGroup{
		{Name: "General Purpose", Description: "Most Popular"},
		{Name: "Developer", Description: "Budget-Friendly"},
		{Name: "High CPU", Description: "CPU-Optimized"},
		{Name: "High Memory", Description: "Memory-Optimized"},
	}

	for _, plan := range plans {
		// Skip GPU and Cloud Native plans as requested
		if strings.HasPrefix(plan.Name, "GPU-") ||
			strings.HasPrefix(plan.Name, "CLOUDNATIVE-") {
			continue
		}

		// Group based on plan name prefix
		switch {
		case strings.HasPrefix(plan.Name, "DEV-"):
			groups[1].Plans = append(groups[1].Plans, plan)
		case strings.HasPrefix(plan.Name, "HICPU-"):
			groups[2].Plans = append(groups[2].Plans, plan)
		case strings.HasPrefix(plan.Name, "HIMEM-"):
			groups[3].Plans = append(groups[3].Plans, plan)
		default:
			groups[0].Plans = append(groups[0].Plans, plan) // General purpose
		}
	}

	// Remove empty groups
	var filteredGroups []PlanGroup
	for _, group := range groups {
		if len(group.Plans) > 0 {
			filteredGroups = append(filteredGroups, group)
		}
	}

	return filteredGroups
}

// renderOSTemplateSelection renders the OS template selection view
func (m tuiModel) renderOSTemplateSelection() string {
	var b strings.Builder

	// Header with breadcrumb
	breadcrumb := "Server List > Create Server > Select OS Template"
	b.WriteString(headerStyle.Render(breadcrumb))
	b.WriteString("\n\n")

	// Show error if any
	if m.createError != "" {
		b.WriteString(ui.DefaultErrorColours.Sprint("Error: " + m.createError))
		b.WriteString("\n\n")
	}

	// Search/filter info
	b.WriteString(fmt.Sprintf("Available OS Templates (%d total):\n", len(m.templates)))
	b.WriteString("Select an operating system template for your server\n\n")

	// Table header
	b.WriteString(fmt.Sprintf("   %-50s %-12s %-8s %s\n",
		"Template Name", "Size", "Access", "Type"))
	b.WriteString("   " + strings.Repeat("─", 85) + "\n")

	// Calculate terminal height for scrolling
	termHeight := terminal.GetTerminalHeight()
	if termHeight <= 0 {
		termHeight = 24 // Default fallback
	}

	// Reserve space for header, breadcrumb, search info, table header, help text
	availableLines := termHeight - 8
	if availableLines < 5 {
		availableLines = 5
	}

	// Apply scrolling to filtered templates
	startIdx := m.osScrollOffset
	endIdx := startIdx + availableLines
	if endIdx > len(m.filteredTemplates) {
		endIdx = len(m.filteredTemplates)
	}

	// Render visible templates
	for i := startIdx; i < endIdx; i++ {
		template := m.filteredTemplates[i]

		// Truncate long template names
		templateName := template.Title
		if len(templateName) > 50 {
			templateName = templateName[:47] + "..."
		}

		// Format size in GB
		sizeGB := fmt.Sprintf("%d GB", template.Size)

		templateLine := fmt.Sprintf("%-50s %-12s %-8s %s",
			templateName,
			sizeGB,
			string(template.Access),
			string(template.Type))

		if i == m.selected {
			b.WriteString(selectedStyle.Render("> " + templateLine))
		} else {
			b.WriteString(normalStyle.Render("  " + templateLine))
		}
		b.WriteString("\n")
	}

	// Show scroll indicators
	if startIdx > 0 {
		b.WriteString(helpStyle.Render("   ↑ More templates above\n"))
	}
	if endIdx < len(m.filteredTemplates) {
		b.WriteString(helpStyle.Render("   ↓ More templates below\n"))
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate • enter: select • esc: back"))

	return b.String()
}

// updateOSScrollOffset updates the scroll offset to keep the selected OS template visible
func (m *tuiModel) updateOSScrollOffset() {
	termHeight := terminal.GetTerminalHeight()
	if termHeight <= 0 {
		termHeight = 24
	}

	availableLines := termHeight - 8 // Reserve space for headers and UI
	if availableLines < 5 {
		availableLines = 5
	}

	selectedIndex := m.selected

	// Adjust scroll offset to keep selected item visible
	if selectedIndex < m.osScrollOffset {
		m.osScrollOffset = selectedIndex
	} else if selectedIndex >= m.osScrollOffset+availableLines {
		m.osScrollOffset = selectedIndex - availableLines + 1
		if m.osScrollOffset < 0 {
			m.osScrollOffset = 0
		}
	}
}

// isKubernetesTemplate checks if a template title indicates it's a Kubernetes template
func isKubernetesTemplate(title string) bool {
	title = strings.ToLower(title)
	return strings.Contains(title, "k8s") || strings.Contains(title, "kubernetes")
}

// isGPUTemplate checks if a template title indicates it's a GPU-optimized template
func isGPUTemplate(title string) bool {
	title = strings.ToLower(title)
	return strings.Contains(title, "nvidia") || strings.Contains(title, "cuda") || strings.Contains(title, "gpu")
}

// sortTemplatesByPriority sorts OS templates with Linux distributions first, then Windows
func sortTemplatesByPriority(templates []upcloud.Storage) {
	sort.Slice(templates, func(i, j int) bool {
		titleI := strings.ToLower(templates[i].Title)
		titleJ := strings.ToLower(templates[j].Title)

		// Check if either is Windows
		isWindowsI := strings.Contains(titleI, "windows")
		isWindowsJ := strings.Contains(titleJ, "windows")

		// Windows templates go to the bottom
		if isWindowsI && !isWindowsJ {
			return false
		}
		if !isWindowsI && isWindowsJ {
			return true
		}

		// If both are Windows or both are not Windows, sort by specific priority
		if isWindowsI && isWindowsJ {
			// Both Windows - sort alphabetically
			return titleI < titleJ
		}

		// Both are Linux - prioritize by popularity
		priorityI := getLinuxPriority(titleI)
		priorityJ := getLinuxPriority(titleJ)

		if priorityI != priorityJ {
			return priorityI < priorityJ // Lower number = higher priority
		}

		// Same priority - sort alphabetically
		return titleI < titleJ
	})
}

// getLinuxPriority returns priority order for Linux distributions (lower = higher priority)
func getLinuxPriority(title string) int {
	title = strings.ToLower(title)

	// Ubuntu gets highest priority
	if strings.Contains(title, "ubuntu") {
		if strings.Contains(title, "24.04") {
			return 1 // Ubuntu 24.04 LTS first
		}
		if strings.Contains(title, "22.04") {
			return 2 // Ubuntu 22.04 LTS second
		}
		if strings.Contains(title, "20.04") {
			return 3 // Ubuntu 20.04 LTS third
		}
		return 4 // Other Ubuntu versions
	}

	// Debian second priority
	if strings.Contains(title, "debian") {
		if strings.Contains(title, "12") {
			return 5 // Debian 12 (current stable)
		}
		if strings.Contains(title, "11") {
			return 6 // Debian 11
		}
		return 7 // Other Debian versions
	}

	// CentOS Stream
	if strings.Contains(title, "centos") {
		return 8
	}

	// AlmaLinux
	if strings.Contains(title, "almalinux") {
		return 9
	}

	// Rocky Linux
	if strings.Contains(title, "rocky") {
		return 10
	}

	// Fedora
	if strings.Contains(title, "fedora") {
		return 11
	}

	// Everything else
	return 12
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
	fmt.Printf("\n\n[1] Back to server actions  [2] Back to server list\n")
	fmt.Printf("Choose option (1-2): ")

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

// loadCreateWizardDataMsg is a message for loading wizard prerequisites
type loadCreateWizardDataMsg struct {
	zones     []upcloud.Zone
	plans     []upcloud.Plan
	templates []upcloud.Storage
	err       error
}

// createServerMsg is a message for server creation results
type createServerMsg struct {
	server *upcloud.ServerDetails
	err    error
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
		fmt.Printf("\nWARNING: Are you sure you want to delete %s?\n", server.Hostname)
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
	default:
		return nil, fmt.Errorf("unknown action: %s", action.Command)
	}
}
