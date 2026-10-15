package metallb

import (
	"context"
	"fmt"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	metallbdiagnostic "github.com/andrewbytecoder/kdig/pkg/metallb"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Options struct {
	Namespace    string
	PendingFor   time.Duration
	FRRContainer string
}

func NewOptions() *Options {
	return &Options{
		Namespace:    "metallb-system",
		PendingFor:   2 * time.Minute,
		FRRContainer: "frr",
	}
}

func NewCommand(commonOptions *common.Options, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "metallb",
		Short: "Diagnose MetalLB controllers, speakers, configuration, and services",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			clients, err := commonOptions.Clients()
			if err != nil {
				return err
			}
			return commonOptions.WriteReport(options.Report(command.Context(), clients, commonOptions.EventSince))
		},
	}
	options.AddCommandFlags(command.Flags())
	return command
}

func (options *Options) AddCommandFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "MetalLB namespace")
	flags.DurationVar(&options.PendingFor, "pending-for", options.PendingFor, "Ignore newer LoadBalancer services without an external address")
	flags.StringVar(&options.FRRContainer, "frr-container", options.FRRContainer, "FRR container name in MetalLB speaker pods")
}

func (options *Options) Validate() error {
	if options.PendingFor < 0 {
		return fmt.Errorf("pending-for cannot be negative")
	}
	if options.FRRContainer == "" {
		return fmt.Errorf("frr-container cannot be empty")
	}
	return nil
}

func (options *Options) Report(ctx context.Context, clients *kube.Clients, eventSince time.Duration) diagnostic.Report {
	return metallbdiagnostic.NewChecker(clients, metallbdiagnostic.Options{
		Namespace:    options.Namespace,
		EventSince:   eventSince,
		PendingFor:   options.PendingFor,
		FRRContainer: options.FRRContainer,
	}).Run(ctx)
}
