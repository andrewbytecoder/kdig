package netcap

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/cli/common"
	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	netcapdiagnostic "github.com/andrewbytecoder/kdig/pkg/netcap"
	"github.com/andrewbytecoder/kdig/pkg/podinfo"
	"github.com/spf13/cobra"
)

type Options struct {
	Namespace           string
	Pod                 string
	Container           string
	OutputFile          string
	Protocol            string
	Port                int
	SourcePort          int
	DestinationPort     int
	Host                string
	SourceHost          string
	DestinationHost     string
	Interface           string
	Count               int
	SnapLength          int
	Duration            time.Duration
	Filter              string
	Overwrite           bool
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
		Interface:      "any",
		Username:       "root",
		KnownHostsFile: defaultKnownHostsFile(),
		SSHPort:        22,
	}
}

func NewCommand(commonOptions *common.Options, options *Options) *cobra.Command {
	command := &cobra.Command{
		Use:   "netcap",
		Short: "Capture packets from a Pod network namespace to a local pcap file",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			clients, err := commonOptions.Clients()
			if err != nil {
				return err
			}
			var progress io.Writer = commonOptions.Out
			if commonOptions.Output == "json" {
				progress = command.ErrOrStderr()
			}
			return commonOptions.WriteReport(options.Report(command.Context(), clients, commonOptions.RequestTimeout, progress))
		},
	}

	flags := command.Flags()
	flags.StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Pod namespace")
	flags.StringVarP(&options.Pod, "pod", "p", options.Pod, "Pod name")
	flags.StringVar(&options.Container, "container", options.Container, "Container used to resolve the Pod network namespace")
	flags.StringVarP(&options.OutputFile, "write", "w", options.OutputFile, "Local pcap file (default POD.pcap)")
	flags.StringVar(&options.Protocol, "protocol", options.Protocol, "Protocol filter: tcp, udp, icmp, icmp6, arp, ip, or ip6")
	flags.IntVar(&options.Port, "port", options.Port, "Source or destination port")
	flags.IntVar(&options.SourcePort, "src-port", options.SourcePort, "Source port")
	flags.IntVar(&options.DestinationPort, "dst-port", options.DestinationPort, "Destination port")
	flags.StringVar(&options.Host, "host", options.Host, "Source or destination host")
	flags.StringVar(&options.SourceHost, "src-host", options.SourceHost, "Source host")
	flags.StringVar(&options.DestinationHost, "dst-host", options.DestinationHost, "Destination host")
	flags.StringVarP(&options.Interface, "interface", "i", options.Interface, "Interface inside the Pod network namespace")
	flags.IntVarP(&options.Count, "count", "c", options.Count, "Stop after this many packets; zero runs until Ctrl+C or duration")
	flags.IntVarP(&options.SnapLength, "snaplen", "s", options.SnapLength, "Capture bytes per packet; zero uses tcpdump default")
	flags.DurationVar(&options.Duration, "duration", options.Duration, "Maximum capture duration; zero runs until Ctrl+C")
	flags.StringVar(&options.Filter, "filter", options.Filter, "Additional tcpdump BPF expression")
	flags.BoolVar(&options.Overwrite, "overwrite", options.Overwrite, "Replace an existing local pcap file")
	flags.StringVarP(&options.Username, "username", "u", options.Username, "SSH username")
	flags.StringVar(&options.Password, "password", options.Password, "SSH password; empty uses SSH agent or private key (may be visible in shell history)")
	flags.StringVar(&options.IdentityFile, "identity-file", options.IdentityFile, "SSH private key file")
	flags.StringVar(&options.KnownHostsFile, "known-hosts", options.KnownHostsFile, "SSH known_hosts file; unknown host keys are added automatically")
	flags.IntVar(&options.SSHPort, "ssh-port", options.SSHPort, "SSH port")
	flags.BoolVar(&options.InsecureSkipHostKey, "insecure-skip-host-key", options.InsecureSkipHostKey, "Skip SSH host key verification")
	return command
}

func (options *Options) Validate() error {
	if options.Namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if options.Pod == "" {
		return fmt.Errorf("pod is required")
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
	return netcapdiagnostic.ValidateCaptureOptions(options.captureOptions())
}

func (options *Options) Report(ctx context.Context, clients *kube.Clients, requestTimeout time.Duration, progress io.Writer) diagnostic.Report {
	runner := podinfo.NewSSHStreamRunner(podinfo.SSHOptions{
		Username:            options.Username,
		Password:            options.Password,
		IdentityFile:        options.IdentityFile,
		KnownHostsFile:      options.KnownHostsFile,
		InsecureSkipHostKey: options.InsecureSkipHostKey,
		Timeout:             requestTimeout,
	})
	return netcapdiagnostic.NewCapturer(clients, runner, netcapdiagnostic.Options{
		Namespace:      options.Namespace,
		Pod:            options.Pod,
		Container:      options.Container,
		OutputFile:     options.OutputFile,
		CaptureOptions: options.captureOptions(),
		Overwrite:      options.Overwrite,
		SSHPort:        options.SSHPort,
		Progress:       progress,
	}).Run(ctx)
}

func (options *Options) captureOptions() netcapdiagnostic.CaptureOptions {
	return netcapdiagnostic.CaptureOptions{
		Protocol:        options.Protocol,
		Port:            options.Port,
		SourcePort:      options.SourcePort,
		DestinationPort: options.DestinationPort,
		Host:            options.Host,
		SourceHost:      options.SourceHost,
		DestinationHost: options.DestinationHost,
		Interface:       options.Interface,
		Count:           options.Count,
		SnapLength:      options.SnapLength,
		Duration:        options.Duration,
		Filter:          options.Filter,
	}
}

func defaultKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}
