// Package network holds the `network` CLI command group.
package network

import (
	"context"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/spf13/cobra"
)

// ServiceFactory lazily builds a Service so that --help needs no credentials.
type ServiceFactory func(ctx context.Context) (cloud.Service, error)

// NewCommand builds the `network` parent command (read-only in v1).
func NewCommand(factory ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Inspect networks",
	}
	cmd.AddCommand(
		NewListCommand(factory),
		NewShowCommand(factory),
	)
	return cmd
}
