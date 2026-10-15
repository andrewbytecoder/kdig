package cli

import (
	amtoolcmd "github.com/andrewbytecoder/kdig/pkg/cli/amtool"
	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	metallbcmd "github.com/andrewbytecoder/kdig/pkg/cli/metallb"
	netcapcmd "github.com/andrewbytecoder/kdig/pkg/cli/netcap"
	podinfocmd "github.com/andrewbytecoder/kdig/pkg/cli/podinfo"
	prometheuscmd "github.com/andrewbytecoder/kdig/pkg/cli/prometheus"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	commonOptions := common.NewOptions()
	amtoolOptions := amtoolcmd.NewOptions()
	metalLBOptions := metallbcmd.NewOptions()
	netcapOptions := netcapcmd.NewOptions()
	podInfoOptions := podinfocmd.NewOptions()
	prometheusOptions := prometheuscmd.NewOptions()
	command := &cobra.Command{
		Use:           "kubectl-dig",
		Short:         "Diagnose Kubernetes workloads and common add-on problems",
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
	command.AddCommand(netcapcmd.NewCommand(commonOptions, netcapOptions))
	command.AddCommand(podinfocmd.NewCommand(commonOptions, podInfoOptions))
	command.AddCommand(prometheuscmd.NewCommand(commonOptions, prometheusOptions))
	return command
}
