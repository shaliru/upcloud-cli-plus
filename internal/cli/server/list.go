package server

import (
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

// NewListCommand builds `server list`.
func NewListCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			servers, err := svc.ListServers(cmd.Context())
			if err != nil {
				return err
			}
			switch output.Format(format) {
			case output.FormatJSON:
				return output.JSON(cmd.OutOrStdout(), servers)
			case output.FormatYAML:
				return output.YAML(cmd.OutOrStdout(), servers)
			default:
				return output.ServersTable(cmd.OutOrStdout(), servers)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "Output format: table, json, yaml")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on servers")
	return cmd
}
