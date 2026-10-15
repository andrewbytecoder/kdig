package amtool

import (
	"context"
	"fmt"

	alertmanagerdiagnostic "github.com/andrewbytecoder/kdig/pkg/amtool"
	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	"github.com/spf13/cobra"
)

type Options struct {
	Namespace       string
	StatefulSet     string
	Container       string
	AlertmanagerURL string
}

func NewOptions() *Options {
	return &Options{
		Namespace:       "monitoring",
		StatefulSet:     "alertmanager-main",
		Container:       "alertmanager",
		AlertmanagerURL: "http://localhost:9093",
	}
}

func NewCommand(commonOptions *common.Options, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "amtool",
		Short: "Diagnose Alertmanager alerts, configuration, routes, and silences",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			clients, err := commonOptions.Clients()
			if err != nil {
				return err
			}
			return commonOptions.WriteReport(options.Report(command.Context(), clients))
		},
	}

	flags := command.Flags()
	flags.StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Alertmanager namespace")
	flags.StringVar(&options.StatefulSet, "statefulset", options.StatefulSet, "Alertmanager StatefulSet name")
	flags.StringVar(&options.Container, "container", options.Container, "Container that provides amtool")
	flags.StringVar(&options.AlertmanagerURL, "alertmanager-url", options.AlertmanagerURL, "Alertmanager URL reachable from each pod")
	return command
}

func (options *Options) Validate() error {
	if options.Namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if options.StatefulSet == "" {
		return fmt.Errorf("statefulset cannot be empty")
	}
	if options.Container == "" {
		return fmt.Errorf("container cannot be empty")
	}
	if options.AlertmanagerURL == "" {
		return fmt.Errorf("alertmanager-url cannot be empty")
	}
	return nil
}

func (options *Options) Report(ctx context.Context, clients *kube.Clients) diagnostic.Report {
	return alertmanagerdiagnostic.NewChecker(clients, alertmanagerdiagnostic.Options{
		Namespace:       options.Namespace,
		StatefulSet:     options.StatefulSet,
		Container:       options.Container,
		AlertmanagerURL: options.AlertmanagerURL,
	}).Run(ctx)
}
