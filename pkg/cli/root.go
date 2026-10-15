package cli

import (
	"context"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	metallbcmd "github.com/andrewbytecoder/kdig/pkg/cli/metallb"
	prometheuscmd "github.com/andrewbytecoder/kdig/pkg/cli/prometheus"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/spf13/cobra"
)

type rootOptions struct {
	common     *common.Options
	metallb    *metallbcmd.Options
	prometheus *prometheuscmd.Options
}

func NewRootCommand() *cobra.Command {
	options := &rootOptions{
		common:     common.NewOptions(),
		metallb:    metallbcmd.NewOptions(),
		prometheus: prometheuscmd.NewOptions(),
	}
	command := &cobra.Command{
		Use:           "kubectl-dig",
		Short:         "Diagnose common Kubernetes add-on problems",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return options.runAll(command.Context())
		},
	}

	options.common.AddFlags(command.PersistentFlags())
	options.metallb.AddRootFlags(command.Flags())
	options.prometheus.AddRootFlags(command.Flags())
	command.AddCommand(metallbcmd.NewCommand(options.common, options.metallb))
	command.AddCommand(prometheuscmd.NewCommand(options.common, options.prometheus))
	return command
}

func (options *rootOptions) runAll(ctx context.Context) error {
	if err := options.metallb.Validate(); err != nil {
		return err
	}
	clients, err := options.common.Clients()
	if err != nil {
		return err
	}

	metalLBReport := options.metallb.Report(ctx, clients, options.common.EventSince)
	prometheusReport := options.prometheus.Report(
		ctx,
		clients,
		options.common.EventSince,
		options.common.RequestTimeout,
	)
	report := diagnostic.Merge(
		"all",
		options.metallb.Namespace+","+options.prometheus.Namespace,
		metalLBReport,
		prometheusReport,
	)
	return options.common.WriteReport(report)
}
