package storage

import (
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

// NewListCommand builds `storage list`.
func NewListCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			storages, err := svc.ListStorage(cmd.Context())
			if err != nil {
				return err
			}
			switch output.Format(format) {
			case output.FormatJSON:
				return output.JSON(cmd.OutOrStdout(), storages)
			case output.FormatYAML:
				return output.YAML(cmd.OutOrStdout(), storages)
			default:
				return output.StoragesTable(cmd.OutOrStdout(), storages)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "Output format: table, json, yaml")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on storage")
	return cmd
}
