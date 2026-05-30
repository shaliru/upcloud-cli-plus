// Package server holds the `server` CLI command group.
package server

import (
	"context"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/spf13/cobra"
)

// ServiceFactory lazily builds a Service so that --help needs no credentials.
type ServiceFactory func(ctx context.Context) (cloud.Service, error)

// NewCommand builds the `server` parent command with all subcommands.
func NewCommand(factory ServiceFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage servers",
	}
	cmd.AddCommand(
		NewListCommand(factory),
		NewShowCommand(factory),
		NewLifecycleCommand(factory, "start"),
		NewLifecycleCommand(factory, "stop"),
		NewLifecycleCommand(factory, "restart"),
	)
	return cmd
}
