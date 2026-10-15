package cli

import (
	amtoolcmd "github.com/andrewbytecoder/kdig/pkg/cli/amtool"
	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	metallbcmd "github.com/andrewbytecoder/kdig/pkg/cli/metallb"
	prometheuscmd "github.com/andrewbytecoder/kdig/pkg/cli/prometheus"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	commonOptions := common.NewOptions()
	amtoolOptions := amtoolcmd.NewOptions()
	metalLBOptions := metallbcmd.NewOptions()
	prometheusOptions := prometheuscmd.NewOptions()
	command := &cobra.Command{
		Use:           "kubectl-dig",
		Short:         "Diagnose common Kubernetes add-on problems",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return command.Help()
		},
	}

	commonOptions.AddFlags(command.PersistentFlags())
	command.AddCommand(amtoolcmd.NewCommand(commonOptions, amtoolOptions))
	command.AddCommand(metallbcmd.NewCommand(commonOptions, metalLBOptions))
	command.AddCommand(prometheuscmd.NewCommand(commonOptions, prometheusOptions))
	return command
}
