package server

import (
	"context"
	"fmt"

	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/spf13/cobra"
)

// FailureCountError carries the number of failed operations so the root command
// can map it to an exit code in the 1–99 range.
type FailureCountError struct {
	Count int
}

func (e FailureCountError) Error() string {
	return fmt.Sprintf("%d operation(s) failed", e.Count)
}

func actionFn(svc cloud.Service, action string) func(context.Context, string) error {
	switch action {
	case "start":
		return svc.StartServer
	case "stop":
		return svc.StopServer
	default:
		return svc.RestartServer
	}
}

// NewLifecycleCommand builds `server start|stop|restart <server>...`.
func NewLifecycleCommand(factory ServiceFactory, action string) *cobra.Command {
	return &cobra.Command{
		Use:   action + " <server>...",
		Short: fmt.Sprintf("%s one or more servers", action),
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := factory(cmd.Context())
			if err != nil {
				return err
			}
			do := actionFn(svc, action)

			failures := 0
			for _, ref := range args {
				uuid, err := cloud.ResolveServer(cmd.Context(), svc, ref)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", ref, err)
					failures++
					continue
				}
				if err := do(cmd.Context(), uuid); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", ref, err)
					failures++
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s ok (%s)\n", ref, action, uuid)
			}
			if failures > 0 {
				return FailureCountError{Count: failures}
			}
			return nil
		},
	}
}
