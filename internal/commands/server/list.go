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
	"github.com/jedib0t/go-pretty/v6/table"
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

	// Setup promptui templates for server selection
	templates := &promptui.SelectTemplates{
		Label:    "{{ . | cyan }}",
		Active:   "> {{ printf \"%-38s %-25s %-23s %-9s %-9s %-16s\" .UUID .Hostname .Plan .Zone .State .PublicIP | cyan | bold }}",
		Inactive: "  {{ printf \"%-38s %-25s %-23s %-9s %-9s %-16s\" .UUID .Hostname .Plan .Zone .State .PublicIP | faint }}",
		Selected: "{{ .Hostname | cyan }}",
	}

	searcher := func(input string, index int) bool {
		server := serverItems[index]
		name := strings.Replace(strings.ToLower(server.Hostname), " ", "", -1)
		input = strings.Replace(strings.ToLower(input), " ", "", -1)
		return strings.Contains(name, input)
	}

	// Clean, simplified header for server selection
	fmt.Printf("\nServer Selection:\n\n")
	fmt.Printf("Use the arrow keys to navigate: ↓ ↑ → ←, / toggles search, Enter to select, or Ctrl+C to quit\n\n")
	fmt.Printf("    %-38s %-25s %-23s %-9s %-9s %s\n", "UUID", "Hostname", "Plan", "Zone", "State", "Public IPv4")
	fmt.Printf("    %s %s %s %s %s %s\n",
		strings.Repeat("─", 38),
		strings.Repeat("─", 25),
		strings.Repeat("─", 23),
		strings.Repeat("─", 9),
		strings.Repeat("─", 9),
		strings.Repeat("─", 16))

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
		// User cancelled selection - exit cleanly
		fmt.Println() // Add a newline for clean separation
		return output.OnlyMarshaled{Value: ""}, nil
	}

	selectedServer := serverItems[index]

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
	// Clear the previous interface and show selected server summary in a beautiful table
	fmt.Print("\033[2J\033[H") // Clear screen and move cursor to top

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

// createBoxedTable creates a table with a nice boxed style and fixed width
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

	// Set fixed column widths to prevent border shifting
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: 17, WidthMin: 17}, // Fixed width for labels
		{Number: 2, WidthMax: 75, WidthMin: 75}, // Fixed width for values
	})

	return t
}

// showEnhancedServerDetails displays server information in beautiful ASCII tables
func (ls *listCommand) showEnhancedServerDetails(server ServerItem, exec commands.Executor) (output.Output, error) {
	// Get full server details
	fullServer, err := exec.All().GetServerDetails(exec.Context(), &request.GetServerDetailsRequest{UUID: server.UUID})
	if err != nil {
		return nil, err
	}

	// Clear screen and show enhanced details
	fmt.Print("\033[2J\033[H")

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
	case "back":
		// Return to server selection - fetch fresh server list
		servers, err := exec.All().GetServers(exec.Context())
		if err != nil {
			return nil, err
		}
		return ls.handleInteractiveMode(servers, exec)
	case "exit":
		return output.OnlyMarshaled{Value: "Goodbye!"}, nil
	default:
		return nil, fmt.Errorf("unknown action: %s", action.Command)
	}
}
