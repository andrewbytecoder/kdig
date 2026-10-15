package prometheus

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (checker *Checker) checkServices(ctx context.Context, report *diagnostic.Report) {
	services, err := checker.clients.Kubernetes.CoreV1().Services(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("services", "list services", err))
		return
	}
	matched := 0
	for _, service := range services.Items {
		if !isPrometheusComponent(service.Name, service.Labels) {
			continue
		}
		matched++
		if service.Spec.ClusterIP == corev1.ClusterIPNone && len(service.Spec.Selector) == 0 {
			continue
		}
		ready, endpointErr := checker.readyEndpoints(ctx, service)
		if endpointErr != nil {
			report.Add(apiFailure("services", "list endpoint slices", endpointErr))
			continue
		}
		if ready == 0 {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "services",
				Resource:   diagnostic.Resource("service", service.Namespace, service.Name),
				Summary:    "Prometheus service has no ready endpoints",
				Suggestion: "Check the service selector, Prometheus pod readiness, and service target ports.",
			})
		}
	}
	if matched == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "services",
			Summary:    "No Prometheus service was found",
			Suggestion: "Verify the service labels and installation manifests.",
		})
	}
}

func (checker *Checker) readyEndpoints(ctx context.Context, service corev1.Service) (int, error) {
	slices, err := checker.clients.Kubernetes.DiscoveryV1().EndpointSlices(service.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + service.Name})
	if err != nil {
		return 0, err
	}
	ready := 0
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				ready++
			}
		}
	}
	return ready, nil
}

func (checker *Checker) checkStorage(ctx context.Context, report *diagnostic.Report, pods []corev1.Pod) {
	claimNames := make(map[string]struct{})
	for _, pod := range pods {
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil {
				claimNames[volume.PersistentVolumeClaim.ClaimName] = struct{}{}
			}
		}
	}
	for claimName := range claimNames {
		claim, err := checker.clients.Kubernetes.CoreV1().PersistentVolumeClaims(checker.options.Namespace).Get(ctx, claimName, metav1.GetOptions{})
		if err != nil {
			report.Add(apiFailure("storage", "get persistentvolumeclaim "+claimName, err))
			continue
		}
		if claim.Status.Phase != corev1.ClaimBound {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityCritical,
				Check:      "storage",
				Resource:   diagnostic.Resource("persistentvolumeclaim", claim.Namespace, claim.Name),
				Summary:    fmt.Sprintf("Prometheus volume claim is %s", claim.Status.Phase),
				Suggestion: "Inspect PVC events, StorageClass provisioning, access modes, and available capacity.",
			})
		}
	}
}

func (checker *Checker) checkOperatorResources(ctx context.Context, report *diagnostic.Report) {
	prometheuses, err := checker.clients.Dynamic.Resource(prometheusResource).Namespace(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			report.Add(apiFailure("operator-resources", "list Prometheus custom resources", err))
		}
		return
	}
	if len(prometheuses.Items) == 0 {
		return
	}
	report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "operator-resources", Resource: "prometheuses.monitoring.coreos.com", Summary: fmt.Sprintf("Found %d Prometheus custom resources", len(prometheuses.Items))})
	checker.countMonitorResources(ctx, report, serviceMonitorResource, "ServiceMonitor")
	checker.countMonitorResources(ctx, report, podMonitorResource, "PodMonitor")
	checker.countMonitorResources(ctx, report, ruleResource, "PrometheusRule")
}

func (checker *Checker) countMonitorResources(ctx context.Context, report *diagnostic.Report, resource schema.GroupVersionResource, kind string) {
	list, err := checker.clients.Dynamic.Resource(resource).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("operator-resources", "list "+kind+" resources", err))
		return
	}
	severity := diagnostic.SeverityInfo
	suggestion := ""
	if len(list.Items) == 0 && kind != "PrometheusRule" {
		severity = diagnostic.SeverityWarning
		suggestion = "Create monitor resources or verify they are located in namespaces selected by the Prometheus custom resource."
	}
	report.Add(diagnostic.Finding{
		Severity:   severity,
		Check:      "operator-resources",
		Resource:   resource.Resource + "." + resource.Group,
		Summary:    fmt.Sprintf("Found %d %s resources across all namespaces", len(list.Items), kind),
		Suggestion: suggestion,
	})
}

func (checker *Checker) checkEvents(ctx context.Context, report *diagnostic.Report) {
	events, err := checker.clients.Kubernetes.CoreV1().Events(checker.options.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		report.Add(apiFailure("events", "list warning events", err))
		return
	}
	cutoff := time.Now().Add(-checker.options.EventSince)
	for _, event := range events.Items {
		if !isPrometheusEvent(event) {
			continue
		}
		eventTime := event.LastTimestamp.Time
		if event.EventTime.Time.After(eventTime) {
			eventTime = event.EventTime.Time
		}
		if !eventTime.IsZero() && eventTime.Before(cutoff) {
			continue
		}
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityWarning,
			Check:    "events",
			Resource: strings.ToLower(event.InvolvedObject.Kind) + "/" + event.InvolvedObject.Name,
			Summary:  event.Reason,
			Detail:   event.Message,
		})
	}
}

func isPrometheusEvent(event corev1.Event) bool {
	return isPrometheusComponent(event.InvolvedObject.Name, event.Labels) || strings.Contains(strings.ToLower(event.Message), "prometheus")
}
