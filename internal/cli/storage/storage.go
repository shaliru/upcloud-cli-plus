// Package storage holds the `storage` CLI command group.
package storage

import (
	"context"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/spf13/cobra"
)

// ServiceFactory lazily builds a Service so that --help needs no credentials.
type ServiceFactory func(ctx context.Context) (cloud.Service, error)

// NewCommand builds the `storage` parent command (read-only in v1).
func NewCommand(factory ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Inspect storage",
	}
	cmd.AddCommand(
		NewListCommand(factory),
		NewShowCommand(factory),
	)
	return cmd
}
