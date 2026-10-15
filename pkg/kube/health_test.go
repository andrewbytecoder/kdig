package kube

import (
	"testing"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodFindingsDetectsCrashLoop(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "prometheus-0", Namespace: "monitoring"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "prometheus",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			}},
		},
	}

	findings := PodFindings(pod, "pods")
	if !hasSeverity(findings, diagnostic.SeverityCritical) {
		t.Fatalf("PodFindings() did not report a critical finding: %#v", findings)
	}
}

func TestMatchesComponent(t *testing.T) {
	labels := map[string]string{"app.kubernetes.io/component": "speaker"}
	if !MatchesComponent("release-node", labels, "speaker") {
		t.Fatal("MatchesComponent() = false, want true")
	}
}

func hasSeverity(findings []diagnostic.Finding, severity diagnostic.Severity) bool {
	for _, finding := range findings {
		if finding.Severity == severity {
			return true
		}
	}
	return false
}
