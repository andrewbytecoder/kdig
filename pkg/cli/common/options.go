package common

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	"github.com/spf13/pflag"
)

type Options struct {
	Kubeconfig     string
	ContextName    string
	Output         string
	RequestTimeout time.Duration
	EventSince     time.Duration
	Out            io.Writer
}

func NewOptions() *Options {
	return &Options{
		Output:         "text",
		RequestTimeout: 15 * time.Second,
		EventSince:     time.Hour,
		Out:            os.Stdout,
	}
}

func (options *Options) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&options.Kubeconfig, "kubeconfig", options.Kubeconfig, "Path to the kubeconfig file")
	flags.StringVar(&options.ContextName, "context", options.ContextName, "Kubeconfig context to use")
	flags.StringVarP(&options.Output, "output", "o", options.Output, "Output format: text or json")
	flags.DurationVar(&options.RequestTimeout, "request-timeout", options.RequestTimeout, "Timeout for Kubernetes and HTTP requests")
	flags.DurationVar(&options.EventSince, "event-since", options.EventSince, "Include warning events newer than this duration")
}

func (options *Options) Clients() (*kube.Clients, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	return kube.NewClients(kube.ConfigOptions{
		Kubeconfig: options.Kubeconfig,
		Context:    options.ContextName,
		Timeout:    options.RequestTimeout,
	})
}

func (options *Options) Validate() error {
	if options.Output != "text" && options.Output != "json" {
		return fmt.Errorf("unsupported output format %q; use text or json", options.Output)
	}
	if options.RequestTimeout <= 0 {
		return fmt.Errorf("request-timeout must be greater than zero")
	}
	if options.EventSince <= 0 {
		return fmt.Errorf("event-since must be greater than zero")
	}
	return nil
}

func (options *Options) WriteReport(report diagnostic.Report) error {
	if err := diagnostic.Write(options.Out, report, options.Output); err != nil {
		return err
	}
	if code := report.ExitCode(); code != 0 {
		return &diagnostic.StatusError{Code: code}
	}
	return nil
}
