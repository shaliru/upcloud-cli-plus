// Package cli wires the root command and maps results to exit codes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/client"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/service"
	"github.com/shaliru/upcloud-cli-plus/internal/cli/network"
	"github.com/shaliru/upcloud-cli-plus/internal/cli/server"
	"github.com/shaliru/upcloud-cli-plus/internal/cli/storage"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/output"
	"github.com/shaliru/upcloud-cli-plus/internal/config"
	"github.com/shaliru/upcloud-cli-plus/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// shouldLaunchTUI decides whether to open the TUI. The TUI launches only on a
// real terminal, and only when invoked bare or with -i. A non-TTY (piped)
// stdout never launches the TUI, keeping scripts safe.
func shouldLaunchTUI(isTTY, bareInvoke, interactive bool) bool {
	if !isTTY {
		return false
	}
	return bareInvoke || interactive
}

// defaultFactory builds a real Service from resolved credentials.
func defaultFactory(ctx context.Context) (cloud.Service, error) {
	creds, err := config.Load("")
	if err != nil {
		return nil, err
	}
	configs := []client.ConfigFn{}
	if creds.Token != "" {
		configs = append(configs, client.WithBearerAuth(creds.Token))
	} else {
		configs = append(configs, client.WithBasicAuth(creds.Username, creds.Password))
	}
	c := client.New("", "", configs...)
	return cloud.New(service.New(c)), nil
}

func launchTUI(ctx context.Context, factory server.ServiceFactory, resource string) error {
	return tui.Run(ctx, tui.ServiceFactory(factory), resource)
}

func newRootCommand(factory server.ServiceFactory) *cobra.Command {
	var colorMode string
	root := &cobra.Command{
		Use:           "upctl-plus",
		Short:         "Enhanced UpCloud CLI with an interactive dashboard",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch colorMode {
			case "auto", "always", "never":
			default:
				return fmt.Errorf("invalid --color %q: want auto, always, or never", colorMode)
			}
			isTTY := term.IsTerminal(int(os.Stdout.Fd()))
			output.EnableColor(output.ColorDecision(colorMode, isTTY, os.Getenv("NO_COLOR")))
			return nil
		},
	}
	root.PersistentFlags().StringVar(&colorMode, "color", "auto", "Colour output: auto, always, never")
	root.AddCommand(server.NewCommand(factory))
	root.AddCommand(storage.NewCommand(storage.ServiceFactory(factory)))
	root.AddCommand(network.NewCommand(network.ServiceFactory(factory)))
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute() int {
	ctx := context.Background()
	factory := defaultFactory
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	args := os.Args[1:]
	bareInvoke := len(args) == 0
	interactive := hasInteractiveFlag(args)

	if shouldLaunchTUI(isTTY, bareInvoke, interactive) {
		if err := launchTUI(ctx, factory, resourceFromArgs(args)); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return 100
		}
		return 0
	}

	root := newRootCommand(factory)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		return exitCode(err)
	}
	return 0
}

// hasInteractiveFlag reports whether -i/--interactive appears in args.
func hasInteractiveFlag(args []string) bool {
	for _, a := range args {
		if a == "-i" || a == "--interactive" {
			return true
		}
	}
	return false
}

// resourceFromArgs returns the first positional token (e.g. "server"), used to
// deep-link the TUI. Empty for a bare invocation.
func resourceFromArgs(args []string) string {
	for _, a := range args {
		if len(a) > 0 && a[0] != '-' {
			return a
		}
	}
	return ""
}

// exitCode maps an error to upctl's convention: 1–99 for N failures, 100 otherwise.
func exitCode(err error) int {
	var fc server.FailureCountError
	if errors.As(err, &fc) {
		if fc.Count > 99 {
			return 99
		}
		return fc.Count
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	return 100
}
