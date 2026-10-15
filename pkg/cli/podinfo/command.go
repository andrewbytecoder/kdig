package podinfo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	podinfodiagnostic "github.com/andrewbytecoder/kdig/pkg/podinfo"
	"github.com/spf13/cobra"
)

type Options struct {
	Namespace           string
	Username            string
	Password            string
	IdentityFile        string
	KnownHostsFile      string
	SSHPort             int
	InsecureSkipHostKey bool
}

func NewOptions() *Options {
	return &Options{
		Namespace:      "default",
		Username:       "root",
		KnownHostsFile: defaultKnownHostsFile(),
		SSHPort:        22,
	}
}

func NewCommand(commonOptions *common.Options, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "podinfo [POD]",
		Short: "Inspect a pod's containers and network namespace on its node",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			clients, err := commonOptions.Clients()
			if err != nil {
				return err
			}
			pod := ""
			if len(args) == 1 {
				pod = args[0]
			}
			return commonOptions.WriteReport(options.Report(command.Context(), clients, pod, commonOptions.RequestTimeout))
		},
	}

	flags := command.Flags()
	flags.StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Pod namespace")
	flags.StringVarP(&options.Username, "username", "u", options.Username, "SSH username")
	flags.StringVar(&options.Password, "password", options.Password, "SSH password; empty uses SSH agent or private key (may be visible in shell history)")
	flags.StringVarP(&options.IdentityFile, "identity-file", "i", options.IdentityFile, "SSH private key file")
	flags.StringVar(&options.KnownHostsFile, "known-hosts", options.KnownHostsFile, "SSH known_hosts file; unknown host keys are added automatically")
	flags.IntVar(&options.SSHPort, "ssh-port", options.SSHPort, "SSH port")
	flags.BoolVar(&options.InsecureSkipHostKey, "insecure-skip-host-key", options.InsecureSkipHostKey, "Skip SSH host key verification")
	return command
}

func (options *Options) Validate() error {
	if options.Namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if options.Username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if options.SSHPort < 1 || options.SSHPort > 65535 {
		return fmt.Errorf("ssh-port must be between 1 and 65535")
	}
	if !options.InsecureSkipHostKey && options.KnownHostsFile == "" {
		return fmt.Errorf("known-hosts cannot be empty unless insecure-skip-host-key is enabled")
	}
	return nil
}

func (options *Options) Report(ctx context.Context, clients *kube.Clients, pod string, timeout time.Duration) diagnostic.Report {
	return podinfodiagnostic.NewChecker(clients, podinfodiagnostic.Options{
		Namespace:           options.Namespace,
		Pod:                 pod,
		Username:            options.Username,
		Password:            options.Password,
		IdentityFile:        options.IdentityFile,
		KnownHostsFile:      options.KnownHostsFile,
		SSHPort:             options.SSHPort,
		InsecureSkipHostKey: options.InsecureSkipHostKey,
		Timeout:             timeout,
	}, nil).Run(ctx)
}

func defaultKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}
