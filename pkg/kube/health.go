package kube

import (
	"fmt"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	corev1 "k8s.io/api/core/v1"
)

func PodFindings(pod corev1.Pod, check string) []diagnostic.Finding {
	resource := diagnostic.Resource("pod", pod.Namespace, pod.Name)
	findings := make([]diagnostic.Finding, 0)

	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodUnknown {
		findings = append(findings, diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      check,
			Resource:   resource,
			Summary:    fmt.Sprintf("Pod is %s", pod.Status.Phase),
			Detail:     pod.Status.Message,
			Suggestion: "Inspect pod events and container logs.",
		})
	} else if pod.Status.Phase == corev1.PodPending {
		findings = append(findings, diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      check,
			Resource:   resource,
			Summary:    "Pod is Pending",
			Suggestion: "Inspect scheduling events, image pulls, resource requests, and volume mounts.",
		})
	}

	statuses := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	for _, status := range statuses {
		if status.State.Waiting != nil && isSevereWaitingReason(status.State.Waiting.Reason) {
			findings = append(findings, diagnostic.Finding{
				Severity:   diagnostic.SeverityCritical,
				Check:      check,
				Resource:   resource,
				Summary:    fmt.Sprintf("Container %s is waiting: %s", status.Name, status.State.Waiting.Reason),
				Detail:     status.State.Waiting.Message,
				Suggestion: "Inspect the container logs, image settings, mounted configuration, and recent events.",
			})
		}
		if status.RestartCount >= 5 {
			findings = append(findings, diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      check,
				Resource:   resource,
				Summary:    fmt.Sprintf("Container %s restarted %d times", status.Name, status.RestartCount),
				Suggestion: "Inspect current and previous container logs.",
			})
		}
	}

	if pod.Status.Phase == corev1.PodRunning && !isPodReady(pod) {
		findings = append(findings, diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      check,
			Resource:   resource,
			Summary:    "Pod is running but not Ready",
			Suggestion: "Inspect readiness probes, container logs, and pod events.",
		})
	}

	return findings
}

func MatchesComponent(name string, labels map[string]string, components ...string) bool {
	values := []string{name}
	for _, key := range []string{"app", "component", "app.kubernetes.io/name", "app.kubernetes.io/component", "operator.prometheus.io/name"} {
		values = append(values, labels[key])
	}
	for _, value := range values {
		lowerValue := strings.ToLower(value)
		for _, component := range components {
			if strings.Contains(lowerValue, strings.ToLower(component)) {
				return true
			}
		}
	}
	return false
}

func isPodReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func isSevereWaitingReason(reason string) bool {
	switch reason {
	case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "CreateContainerError", "RunContainerError":
		return true
	default:
		return false
	}
}
