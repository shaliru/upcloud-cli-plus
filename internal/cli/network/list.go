package network

import (
	"fmt"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

var validNetworkTypes = map[string]bool{"private": true, "all": true}

// NewListCommand builds `network list`.
func NewListCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool
	var networkType string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List networks (private by default; use --type all for UpCloud infra too)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !validNetworkTypes[networkType] {
				return fmt.Errorf("invalid --type %q: want private or all", networkType)
			}
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			networks, err := svc.ListNetworks(cmd.Context())
			if err != nil {
				return err
			}
			networks = cloud.FilterNetworksByType(networks, networkType)
			switch output.Format(format) {
			case output.FormatJSON:
				return output.JSON(cmd.OutOrStdout(), networks)
			case output.FormatYAML:
				return output.YAML(cmd.OutOrStdout(), networks)
			default:
				return output.NetworksTable(cmd.OutOrStdout(), networks)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "Output format: table, json, yaml")
	cmd.Flags().StringVar(&networkType, "type", "private", "Category: private, all")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on networks")
	return cmd
}
