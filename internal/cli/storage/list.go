package storage

import (
	"fmt"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/spf13/cobra"
)

var validStorageTypes = map[string]bool{"devices": true, "backups": true, "images": true, "all": true}

func storageNoun(t string) string {
	switch t {
	case "backups":
		return "backup"
	case "images":
		return "custom image"
	case "all":
		return "storage item"
	default:
		return "device"
	}
}

// NewListCommand builds `storage list`.
func NewListCommand(factory ServiceFactory) *cobra.Command {
	var format string
	var interactive bool
	var storageType string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List storage (devices by default; use --type)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !validStorageTypes[storageType] {
				return fmt.Errorf("invalid --type %q: want devices, backups, images, or all", storageType)
			}
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			storages, err := svc.ListStorage(cmd.Context())
			if err != nil {
				return err
			}
			storages = cloud.FilterStorageByCategory(storages, storageType)
			switch output.Format(format) {
			case output.FormatJSON:
				return output.JSON(cmd.OutOrStdout(), storages)
			case output.FormatYAML:
				return output.YAML(cmd.OutOrStdout(), storages)
			default:
				return output.StoragesTable(cmd.OutOrStdout(), storages, storageNoun(storageType))
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "Output format: table, json, yaml")
	cmd.Flags().StringVar(&storageType, "type", "devices", "Category: devices, backups, images, all")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Open the interactive TUI focused on storage")
	return cmd
}
