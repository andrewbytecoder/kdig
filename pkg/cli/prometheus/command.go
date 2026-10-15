package prometheus

import (
	"context"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	prometheusdiagnostic "github.com/andrewbytecoder/kdig/pkg/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Options struct {
	Namespace     string
	PrometheusURL string
}

func NewOptions() *Options {
	return &Options{Namespace: "monitoring"}
}

func NewCommand(commonOptions *common.Options, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "prometheus",
		Short: "Diagnose Prometheus workloads, storage, discovery, targets, and rules",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			clients, err := commonOptions.Clients()
			if err != nil {
				return err
			}
			return commonOptions.WriteReport(options.Report(
				command.Context(),
				clients,
				commonOptions.EventSince,
				commonOptions.RequestTimeout,
			))
		},
	}
	options.AddCommandFlags(command.Flags())
	return command
}

func (options *Options) AddRootFlags(flags *pflag.FlagSet) {
	flags.StringVar(&options.Namespace, "prometheus-namespace", options.Namespace, "Prometheus namespace")
	flags.StringVar(&options.PrometheusURL, "prometheus-url", options.PrometheusURL, "Prometheus base URL for target and rule checks")
}

func (options *Options) AddCommandFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Prometheus namespace")
	flags.StringVar(&options.PrometheusURL, "prometheus-url", options.PrometheusURL, "Prometheus base URL for target and rule checks")
}

func (options *Options) Report(
	ctx context.Context,
	clients *kube.Clients,
	eventSince time.Duration,
	requestTimeout time.Duration,
) diagnostic.Report {
	return prometheusdiagnostic.NewChecker(clients, prometheusdiagnostic.Options{
		Namespace:     options.Namespace,
		EventSince:    eventSince,
		PrometheusURL: options.PrometheusURL,
		HTTPTimeout:   requestTimeout,
	}).Run(ctx)
}
