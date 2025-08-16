package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands/network"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/format"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/output"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/ui"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/request"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

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

	// Add exit option at the end of the list
	serverItems = append(serverItems, ServerItem{
		UUID:     "exit",
		Hostname: "Exit interactive mode",
		Plan:     "",
		Zone:     "",
		State:    "",
		PublicIP: "",
		Server:   upcloud.Server{},
	})

	// Server selection prompt
	templates := &promptui.SelectTemplates{
		Label:    "{{ . | cyan }}",
		Active:   "{{ printf \"%-25s %-12s %-15s %-16s %s\" .Hostname .State .Zone .PublicIP .Plan | cyan | bold }}",
		Inactive: "  {{ printf \"%-25s %-12s %-15s %-16s %s\" .Hostname .State .Zone .PublicIP .Plan | faint }}",
		Selected: "{{ .Hostname | cyan }}",
		Details: `
--------- Server Details ----------
{{ "Hostname:" | faint }}	{{ .Hostname }}
{{ "UUID:" | faint }}	{{ .UUID }}
{{ "Plan:" | faint }}	{{ .Plan }}
{{ "Zone:" | faint }}	{{ .Zone }}
{{ "State:" | faint }}	{{ .State }}
{{ "Public IP:" | faint }}	{{ .PublicIP }}`,
	}

	searcher := func(input string, index int) bool {
		server := serverItems[index]
		name := strings.Replace(strings.ToLower(server.Hostname), " ", "", -1)
		input = strings.Replace(strings.ToLower(input), " ", "", -1)
		return strings.Contains(name, input)
	}

	// Print instructions and column headers before the prompt
	fmt.Printf("\nUse the arrow keys to navigate: ↓ ↑ → ← and / toggles search, or select 'Exit interactive mode' to quit\n\n")
	fmt.Printf("    %-25s %-12s %-15s %-16s %s\n", "HOSTNAME", "STATE", "ZONE", "PUBLIC IP", "PLAN")
	fmt.Printf("    %s\n", strings.Repeat("─", 85))

	prompt := promptui.Select{
		Label:     "",
		Items:     serverItems,
		Templates: templates,
		Size:      10,
		Searcher:  searcher,
		HideHelp:  true, // Hide the default promptui help since we're showing our own
	}

	index, _, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("server selection cancelled: %w", err)
	}

	selectedServer := serverItems[index]

	// Handle exit option
	if selectedServer.UUID == "exit" {
		// Exit cleanly with a simple separation
		fmt.Println() // Add a newline for clean separation
		return output.OnlyMarshaled{Value: ""}, nil
	}

	// Show action menu for selected server
	return ls.showActionMenu(selectedServer, exec)
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

// showActionMenu displays available actions for the selected server
func (ls *listCommand) showActionMenu(server ServerItem, exec commands.Executor) (output.Output, error) {
	actions := []ActionItem{
		{Name: "Show details", Command: "show"},
		{Name: "Start server", Command: "start", Enabled: server.State == "stopped"},
		{Name: "Restart server", Command: "restart", Enabled: server.State == "started"},
		{Name: "Stop server", Command: "stop", Enabled: server.State == "started"},
		{Name: "Delete server", Command: "delete", Enabled: true},
		{Name: "Exit", Command: "exit", Enabled: true},
	}

	// Filter enabled actions
	var enabledActions []ActionItem
	for _, action := range actions {
		if action.Enabled {
			enabledActions = append(enabledActions, action)
		}
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . | cyan }}",
		Active:   "{{ .Name | cyan | bold }}{{ if not .Enabled }} (disabled){{ end }}",
		Inactive: "  {{ .Name }}{{ if not .Enabled }} (disabled){{ end }}",
		Selected: "{{ .Name | cyan }}",
	}

	prompt := promptui.Select{
		Label:     fmt.Sprintf("Actions for %s (%s)", server.Hostname, server.State),
		Items:     enabledActions,
		Templates: templates,
		Size:      len(enabledActions),
	}

	index, _, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("action selection cancelled: %w", err)
	}

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

// executeAction performs the selected action on the server
func (ls *listCommand) executeAction(action ActionItem, server ServerItem, exec commands.Executor) (output.Output, error) {
	switch action.Command {
	case "show":
		// Use the existing show command functionality
		showCmd := ShowCommand().(*showCommand)
		return showCmd.Execute(exec, server.UUID)
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
		confirmPrompt := promptui.Prompt{
			Label: fmt.Sprintf("Are you sure you want to delete %s? Type 'yes' to confirm", server.Hostname),
			Validate: func(input string) error {
				if input != "yes" {
					return fmt.Errorf("deletion cancelled")
				}
				return nil
			},
		}

		_, err := confirmPrompt.Run()
		if err != nil {
			return output.OnlyMarshaled{Value: "Deletion cancelled"}, nil
		}

		deleteCmd := DeleteCommand().(*deleteCommand)
		return deleteCmd.Execute(exec, server.UUID)
	case "exit":
		return output.OnlyMarshaled{Value: "Goodbye!"}, nil
	default:
		return nil, fmt.Errorf("unknown action: %s", action.Command)
	}
}
