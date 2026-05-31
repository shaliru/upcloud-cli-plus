package network

import (
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

// NewListCommand builds `network list`.
func NewListCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List networks",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			networks, err := svc.ListNetworks(cmd.Context())
			if err != nil {
				return err
			}
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
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on networks")
	return cmd
}
