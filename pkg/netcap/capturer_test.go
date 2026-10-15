package netcap

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCapturerStreamsPcapToLocalFile(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "capture.pcap")
	runner := &fakeStreamRunner{pcap: testPcap()}
	capturer := NewCapturer(testClients(), runner, Options{
		Namespace:  "apps",
		Pod:        "api-0",
		OutputFile: outputFile,
		SSHPort:    22,
		CaptureOptions: CaptureOptions{
			Protocol:  "tcp",
			Port:      443,
			Interface: "any",
			Count:     10,
			Duration:  5 * time.Second,
		},
	})

	report := capturer.Run(context.Background())

	if report.ExitCode() != 0 {
		t.Fatalf("Run() returned unhealthy report: %#v", report.Findings)
	}
	written, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(written, runner.pcap) {
		t.Fatalf("pcap bytes changed: got %d bytes, want %d", len(written), len(runner.pcap))
	}
	for _, expected := range []string{
		"timeout --signal=INT --kill-after=5s 5s",
		"nsenter -t 4242 -n -- tcpdump",
		"-c 10",
		"'tcp and port 443'",
	} {
		if !strings.Contains(runner.streamCommand, expected) {
			t.Fatalf("capture command does not contain %q: %s", expected, runner.streamCommand)
		}
	}
	if !findingsContain(report.Findings, outputFile) {
		t.Fatalf("report does not contain local pcap path: %#v", report.Findings)
	}
}

func TestCapturerDoesNotOverwriteByDefault(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(outputFile, []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	runner := &fakeStreamRunner{pcap: testPcap()}
	capturer := NewCapturer(testClients(), runner, Options{
		Namespace:  "apps",
		Pod:        "api-0",
		OutputFile: outputFile,
		CaptureOptions: CaptureOptions{
			Interface: "any",
			Duration:  time.Second,
		},
	})

	report := capturer.Run(context.Background())

	if report.ExitCode() != 2 {
		t.Fatalf("ExitCode() = %d, want 2", report.ExitCode())
	}
	if len(runner.commands) != 0 || runner.streamCommand != "" {
		t.Fatalf("remote runner was called before existing-file validation: %#v %q", runner.commands, runner.streamCommand)
	}
}

func TestCapturerSavesPartialPcapWhenInterrupted(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "partial.pcap")
	runner := &fakeStreamRunner{pcap: testPcap(), streamErr: context.Canceled}
	capturer := NewCapturer(testClients(), runner, Options{
		Namespace:  "apps",
		Pod:        "api-0",
		OutputFile: outputFile,
		CaptureOptions: CaptureOptions{
			Interface: "any",
			Duration:  time.Minute,
		},
	})

	report := capturer.Run(context.Background())

	if report.ExitCode() != 1 {
		t.Fatalf("ExitCode() = %d, want warning exit code 1", report.ExitCode())
	}
	if _, err := os.Stat(outputFile); err != nil {
		t.Fatalf("partial pcap was not saved: %v", err)
	}
	if !findingsContain(report.Findings, "partial pcap saved") {
		t.Fatalf("report does not describe partial capture: %#v", report.Findings)
	}
}

func TestCapturerReportsHeaderOnlyPcapAsEmpty(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "empty.pcap")
	runner := &fakeStreamRunner{pcap: testPcapHeader()}
	capturer := NewCapturer(testClients(), runner, Options{
		Namespace:  "apps",
		Pod:        "api-0",
		OutputFile: outputFile,
		CaptureOptions: CaptureOptions{
			Interface: "any",
			Duration:  time.Second,
		},
	})

	report := capturer.Run(context.Background())

	if report.ExitCode() != 1 {
		t.Fatalf("ExitCode() = %d, want warning exit code 1", report.ExitCode())
	}
	for _, expected := range []string{"No packets were captured", "Packets captured: 0", "snapshot length is a per-packet limit"} {
		if !findingsContain(report.Findings, expected) {
			t.Fatalf("empty capture report does not contain %q: %#v", expected, report.Findings)
		}
	}
}

func TestBuildCaptureCommandQuotesAdditionalFilter(t *testing.T) {
	options := CaptureOptions{
		Interface: "eth0",
		Duration:  1500 * time.Millisecond,
		Filter:    "tcp or udp; echo unsafe",
	}
	command := BuildCaptureCommand(123, options)
	if !strings.Contains(command, "2s nsenter -t 123 -n") {
		t.Fatalf("duration was not rounded up: %s", command)
	}
	if !strings.Contains(command, "'(tcp or udp; echo unsafe)'") {
		t.Fatalf("additional filter was not shell quoted: %s", command)
	}
}

func TestBuildCaptureCommandWithoutDurationRunsUntilInterrupted(t *testing.T) {
	command := BuildCaptureCommand(123, CaptureOptions{Interface: "any"})
	if strings.Contains(command, "timeout") || strings.Contains(command, "sh -c") {
		t.Fatalf("unlimited capture unexpectedly contains timeout wrapper: %s", command)
	}
	if !strings.HasPrefix(command, "nsenter -t 123 -n -- tcpdump") {
		t.Fatalf("unexpected unlimited capture command: %s", command)
	}
	if err := ValidateCaptureOptions(CaptureOptions{Interface: "any"}); err != nil {
		t.Fatalf("ValidateCaptureOptions() rejected unlimited capture: %v", err)
	}
}

func TestValidateCaptureOptions(t *testing.T) {
	tests := []struct {
		name    string
		options CaptureOptions
	}{
		{name: "bad protocol", options: CaptureOptions{Protocol: "http", Interface: "any", Duration: time.Second}},
		{name: "bad port", options: CaptureOptions{Port: 70000, Interface: "any", Duration: time.Second}},
		{name: "bad host", options: CaptureOptions{Host: "example.com;id", Interface: "any", Duration: time.Second}},
		{name: "negative duration", options: CaptureOptions{Interface: "any", Duration: -time.Second}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCaptureOptions(test.options); err == nil {
				t.Fatal("ValidateCaptureOptions() error = nil, want error")
			}
		})
	}
}

type fakeStreamRunner struct {
	commands      []string
	streamCommand string
	pcap          []byte
	streamErr     error
}

func (runner *fakeStreamRunner) Run(_ context.Context, _ string, command string) (string, error) {
	runner.commands = append(runner.commands, command)
	switch {
	case command == "crictl ps -a -o json":
		return `{"containers":[{"id":"container-api","metadata":{"name":"api","attempt":0},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"pod-uid","io.kubernetes.container.name":"api"}}]}`, nil
	case strings.HasPrefix(command, "crictl inspect "):
		return `{"info":{"pid":2000,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/proc/4242/ns/net"}]}}}}`, nil
	case command == "readlink /proc/4242/ns/net":
		return "net:[4026533000]\n", nil
	default:
		return "", nil
	}
}

func (runner *fakeStreamRunner) Stream(_ context.Context, _ string, command string, stdout io.Writer) (string, error) {
	runner.streamCommand = command
	_, err := stdout.Write(runner.pcap)
	if err != nil {
		return "", err
	}
	return "10 packets captured", runner.streamErr
}

func testClients() *kube.Clients {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "apps", UID: types.UID("pod-uid")},
		Spec: corev1.PodSpec{
			NodeName:   "worker-1",
			Containers: []corev1.Container{{Name: "api"}},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type:    corev1.NodeInternalIP,
			Address: "192.0.2.10",
		}}},
	}
	return &kube.Clients{Kubernetes: fake.NewSimpleClientset(pod, node)}
}

func testPcap() []byte {
	data := append([]byte{}, testPcapHeader()...)
	data = append(data,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
		0xde, 0xad, 0xbe, 0xef,
	)
	return data
}

func testPcapHeader() []byte {
	return []byte{
		0xd4, 0xc3, 0xb2, 0xa1,
		0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
	}
}

func findingsContain(findings []diagnostic.Finding, expected string) bool {
	for _, finding := range findings {
		if strings.Contains(finding.Resource, expected) || strings.Contains(finding.Summary, expected) || strings.Contains(finding.Detail, expected) || strings.Contains(finding.Suggestion, expected) {
			return true
		}
	}
	return false
}
