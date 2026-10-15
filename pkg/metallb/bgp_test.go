package metallb

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const bgpSummaryFixture = `IPv4 Unicast Summary (VRF default):
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd PfxSnt Desc
10.0.0.1       4      64512       100       100        0    0    0  01:02:03           12       8 router-a
10.0.0.2       4      64513         0         0        0    0    0     never       Active       0 router-b`

func TestParseBGPSummary(t *testing.T) {
	neighbors := parseBGPSummary(bgpSummaryFixture)
	if len(neighbors) != 2 {
		t.Fatalf("parseBGPSummary() returned %d neighbors, want 2", len(neighbors))
	}
	if !neighbors[0].established || neighbors[0].state != "12" {
		t.Fatalf("first neighbor = %#v, want established with 12 prefixes", neighbors[0])
	}
	if neighbors[1].established || neighbors[1].state != "Active" {
		t.Fatalf("second neighbor = %#v, want Active", neighbors[1])
	}
}

func TestCheckSpeakerBGPCollectsFRROutput(t *testing.T) {
	checker := &Checker{
		clients: &kube.Clients{PodExec: fakePodExecutor{}},
		options: Options{Namespace: "metallb-system", FRRContainer: "frr"},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "metallb-speaker-a", Namespace: "metallb-system"},
		Spec: corev1.PodSpec{
			NodeName:   "worker-a",
			Containers: []corev1.Container{{Name: "frr"}},
		},
	}
	report := diagnostic.Report{}

	checker.checkSpeakerBGP(context.Background(), &report, pod)

	if findingCount(report.Findings, "bgp-sessions", diagnostic.SeverityInfo) == 0 {
		t.Fatalf("expected BGP summary finding, got %#v", report.Findings)
	}
	if findingCount(report.Findings, "bgp-neighbors", diagnostic.SeverityCritical) != 1 {
		t.Fatalf("expected one failed BGP neighbor, got %#v", report.Findings)
	}
	if findingCount(report.Findings, "advertised-routes", diagnostic.SeverityInfo) != 2 {
		t.Fatalf("expected advertised routes for both neighbors, got %#v", report.Findings)
	}
}

type fakePodExecutor struct{}

func (fakePodExecutor) Exec(_ context.Context, _, _, _ string, command []string) (string, string, error) {
	joined := strings.Join(command, " ")
	switch {
	case strings.Contains(joined, "show bgp summary"):
		return bgpSummaryFixture, "", nil
	case strings.Contains(joined, "advertised-routes"):
		return "Network Next Hop\n*> 10.20.0.0/24 0.0.0.0", "", nil
	case strings.Contains(joined, "show bgp ipv4 unicast"):
		return "BGP table version is 1", "", nil
	default:
		return "", "", nil
	}
}

func findingCount(findings []diagnostic.Finding, check string, severity diagnostic.Severity) int {
	count := 0
	for _, finding := range findings {
		if finding.Check == check && finding.Severity == severity {
			count++
		}
	}
	return count
}
