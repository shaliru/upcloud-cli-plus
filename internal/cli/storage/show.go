package storage

import (
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

// NewShowCommand builds `storage show <ref>`.
func NewShowCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "show <storage>",
		Short: "Show details of a storage (by UUID or title)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			uuid, err := cloud.ResolveStorage(cmd.Context(), svc, args[0])
			if err != nil {
				return err
			}
			details, err := svc.GetStorage(cmd.Context(), uuid)
			if err != nil {
				return err
			}
			switch output.Format(format) {
			case output.FormatJSON:
				return output.JSON(cmd.OutOrStdout(), details)
			case output.FormatYAML:
				return output.YAML(cmd.OutOrStdout(), details)
			default:
				return output.StorageDetailsText(cmd.OutOrStdout(), details)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "Output format: table, json, yaml")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on this storage")
	return cmd
}
