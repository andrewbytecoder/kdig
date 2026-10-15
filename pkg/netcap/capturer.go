package netcap

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	"github.com/andrewbytecoder/kdig/pkg/podinfo"
)

var safeTcpdumpValue = regexp.MustCompile(`^[A-Za-z0-9_.:%-]+$`)

type CaptureOptions struct {
	Protocol        string
	Port            int
	SourcePort      int
	DestinationPort int
	Host            string
	SourceHost      string
	DestinationHost string
	Interface       string
	Count           int
	SnapLength      int
	Duration        time.Duration
	Filter          string
}

type Options struct {
	Namespace      string
	Pod            string
	Container      string
	OutputFile     string
	CaptureOptions CaptureOptions
	Overwrite      bool
	SSHPort        int
}

type Capturer struct {
	clients *kube.Clients
	runner  podinfo.StreamRunner
	options Options
}

func NewCapturer(clients *kube.Clients, runner podinfo.StreamRunner, options Options) *Capturer {
	if options.Namespace == "" {
		options.Namespace = "default"
	}
	if options.SSHPort == 0 {
		options.SSHPort = 22
	}
	if options.CaptureOptions.Interface == "" {
		options.CaptureOptions.Interface = "any"
	}
	return &Capturer{clients: clients, runner: runner, options: options}
}

func (capturer *Capturer) Run(ctx context.Context) (report diagnostic.Report) {
	report = diagnostic.Report{
		Target:    "netcap",
		Namespace: capturer.options.Namespace,
		StartedAt: time.Now(),
	}
	defer report.Complete()

	if err := ValidateCaptureOptions(capturer.options.CaptureOptions); err != nil {
		report.Add(failure("capture-options", diagnostic.Resource("pod", capturer.options.Namespace, capturer.options.Pod), "Invalid capture options", err))
		return
	}
	outputFile := capturer.options.OutputFile
	if outputFile == "" {
		outputFile = capturer.options.Pod + ".pcap"
	}
	absOutput, err := filepath.Abs(outputFile)
	if err != nil {
		report.Add(failure("local-output", outputFile, "Cannot resolve local pcap path", err))
		return
	}
	if !capturer.options.Overwrite {
		if _, statErr := os.Stat(absOutput); statErr == nil {
			report.Add(failure("local-output", absOutput, "Local pcap file already exists", fmt.Errorf("use --overwrite to replace it")))
			return
		} else if !os.IsNotExist(statErr) {
			report.Add(failure("local-output", absOutput, "Cannot inspect local pcap path", statErr))
			return
		}
	}
	target, err := podinfo.ResolveNetworkTarget(
		ctx,
		capturer.clients,
		capturer.runner,
		capturer.options.Namespace,
		capturer.options.Pod,
		capturer.options.Container,
		capturer.options.SSHPort,
	)
	if err != nil {
		report.Add(failure("network-target", diagnostic.Resource("pod", capturer.options.Namespace, capturer.options.Pod), "Cannot resolve Pod network namespace", err))
		return
	}

	directory := filepath.Dir(absOutput)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(absOutput)+".*.tmp")
	if err != nil {
		report.Add(failure("local-output", absOutput, "Cannot create temporary pcap file", err))
		return
	}
	temporaryName := temporary.Name()
	completed := false
	defer func() {
		temporary.Close()
		if !completed {
			os.Remove(temporaryName)
		}
	}()

	command := BuildCaptureCommand(target.NetworkPID, capturer.options.CaptureOptions)
	stderr, captureErr := capturer.runner.Stream(ctx, target.SSHAddress, command, temporary)
	interrupted := errors.Is(captureErr, context.Canceled)
	if captureErr != nil && !interrupted {
		report.Add(failure("capture", diagnostic.Resource("pod", target.Namespace, target.Pod), "tcpdump capture failed", fmt.Errorf("%w: %s", captureErr, strings.TrimSpace(stderr))))
		return
	}
	if err := temporary.Sync(); err != nil {
		report.Add(failure("local-output", absOutput, "Cannot flush local pcap file", err))
		return
	}
	info, err := temporary.Stat()
	if err != nil {
		report.Add(failure("local-output", absOutput, "Cannot inspect temporary pcap file", err))
		return
	}
	if info.Size() < 24 {
		report.Add(failure("capture", diagnostic.Resource("pod", target.Namespace, target.Pod), "Capture did not produce a valid pcap header", fmt.Errorf("received %d bytes", info.Size())))
		return
	}
	if err := temporary.Close(); err != nil {
		report.Add(failure("local-output", absOutput, "Cannot close temporary pcap file", err))
		return
	}
	if capturer.options.Overwrite {
		if err := os.Remove(absOutput); err != nil && !os.IsNotExist(err) {
			report.Add(failure("local-output", absOutput, "Cannot replace existing pcap file", err))
			return
		}
	}
	if err := os.Rename(temporaryName, absOutput); err != nil {
		report.Add(failure("local-output", absOutput, "Cannot finalize local pcap file", err))
		return
	}
	completed = true

	detail := []string{
		"Node: " + target.Node,
		"Node IP: " + target.NodeIP,
		"Container: " + target.Container,
		"CRI container ID: " + target.ContainerID,
		"Network PID: " + strconv.Itoa(target.NetworkPID),
		"Network namespace: " + target.NetworkNamespace,
		"Local pcap: " + absOutput,
		"Bytes written: " + strconv.FormatInt(info.Size(), 10),
		"Remote command: " + command,
	}
	if strings.TrimSpace(stderr) != "" {
		detail = append(detail, "tcpdump: "+strings.TrimSpace(stderr))
	}
	severity := diagnostic.SeverityInfo
	summary := "Packet capture saved to local file"
	if interrupted {
		severity = diagnostic.SeverityWarning
		summary = "Packet capture interrupted; partial pcap saved to local file"
	}
	report.Add(diagnostic.Finding{
		Severity: severity,
		Check:    "capture",
		Resource: diagnostic.Resource("pod", target.Namespace, target.Pod),
		Summary:  summary,
		Detail:   strings.Join(detail, "\n"),
	})
	return
}

func ValidateCaptureOptions(options CaptureOptions) error {
	protocol := strings.ToLower(options.Protocol)
	if protocol != "" {
		allowed := map[string]struct{}{"tcp": {}, "udp": {}, "icmp": {}, "icmp6": {}, "arp": {}, "ip": {}, "ip6": {}}
		if _, ok := allowed[protocol]; !ok {
			return fmt.Errorf("unsupported protocol %q", options.Protocol)
		}
	}
	for name, port := range map[string]int{"port": options.Port, "src-port": options.SourcePort, "dst-port": options.DestinationPort} {
		if port < 0 || port > 65535 {
			return fmt.Errorf("%s must be zero or between 1 and 65535", name)
		}
	}
	if options.Count < 0 {
		return fmt.Errorf("count cannot be negative")
	}
	if options.SnapLength < 0 {
		return fmt.Errorf("snaplen cannot be negative")
	}
	if options.Duration <= 0 {
		return fmt.Errorf("duration must be greater than zero")
	}
	for name, value := range map[string]string{
		"interface": options.Interface,
		"host":      options.Host,
		"src-host":  options.SourceHost,
		"dst-host":  options.DestinationHost,
	} {
		if value != "" && !safeTcpdumpValue.MatchString(value) {
			return fmt.Errorf("%s contains unsupported characters", name)
		}
	}
	return nil
}

func BuildCaptureCommand(networkPID int, options CaptureOptions) string {
	arguments := []string{
		"nsenter", "-t", strconv.Itoa(networkPID), "-n", "--",
		"tcpdump", "-U", "-n", "-i", shellQuote(options.Interface), "-w", "-",
	}
	if options.SnapLength > 0 {
		arguments = append(arguments, "-s", strconv.Itoa(options.SnapLength))
	}
	if options.Count > 0 {
		arguments = append(arguments, "-c", strconv.Itoa(options.Count))
	}
	filters := make([]string, 0)
	if options.Protocol != "" {
		filters = append(filters, strings.ToLower(options.Protocol))
	}
	if options.Port > 0 {
		filters = append(filters, "port "+strconv.Itoa(options.Port))
	}
	if options.SourcePort > 0 {
		filters = append(filters, "src port "+strconv.Itoa(options.SourcePort))
	}
	if options.DestinationPort > 0 {
		filters = append(filters, "dst port "+strconv.Itoa(options.DestinationPort))
	}
	if options.Host != "" {
		filters = append(filters, "host "+options.Host)
	}
	if options.SourceHost != "" {
		filters = append(filters, "src host "+options.SourceHost)
	}
	if options.DestinationHost != "" {
		filters = append(filters, "dst host "+options.DestinationHost)
	}
	if options.Filter != "" {
		filters = append(filters, "("+options.Filter+")")
	}
	if len(filters) > 0 {
		arguments = append(arguments, shellQuote(strings.Join(filters, " and ")))
	}
	command := strings.Join(arguments, " ")
	if options.Duration > 0 {
		seconds := int64(math.Ceil(options.Duration.Seconds()))
		timedCommand := fmt.Sprintf("timeout --signal=INT --kill-after=5s %ds %s", seconds, command)
		command = "sh -c " + shellQuote(timedCommand+`; status=$?; if [ "$status" -eq 124 ] || [ "$status" -eq 130 ]; then exit 0; fi; exit "$status"`)
	}
	return command
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func failure(check, resource, summary string, err error) diagnostic.Finding {
	return diagnostic.Finding{
		Severity: diagnostic.SeverityCritical,
		Check:    check,
		Resource: resource,
		Summary:  summary,
		Detail:   err.Error(),
	}
}
