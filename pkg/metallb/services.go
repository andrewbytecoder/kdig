package metallb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (checker *Checker) checkLoadBalancerServices(ctx context.Context, report *diagnostic.Report, pools map[string]struct{}) []string {
	services, err := checker.clients.Kubernetes.CoreV1().Services(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("loadbalancer-services", "list services", err))
		return nil
	}
	count := 0
	addresses := make([]string, 0)
	for _, service := range services.Items {
		if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		count++
		resource := diagnostic.Resource("service", service.Namespace, service.Name)
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				addresses = append(addresses, ingress.IP)
			} else if ingress.Hostname != "" {
				addresses = append(addresses, ingress.Hostname)
			}
		}
		if len(service.Status.LoadBalancer.Ingress) == 0 && time.Since(service.CreationTimestamp.Time) >= checker.options.PendingFor {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityCritical,
				Check:      "loadbalancer-services",
				Resource:   resource,
				Summary:    "LoadBalancer service has no assigned external address",
				Suggestion: "Check address pool selectors, free addresses, MetalLB controller logs, and service events.",
			})
		}

		poolName := service.Annotations["metallb.io/address-pool"]
		if poolName == "" {
			poolName = service.Annotations["metallb.universe.tf/address-pool"]
		}
		if poolName != "" {
			if _, exists := pools[poolName]; !exists {
				report.Add(diagnostic.Finding{
					Severity:   diagnostic.SeverityCritical,
					Check:      "loadbalancer-services",
					Resource:   resource,
					Summary:    fmt.Sprintf("Service references missing address pool %q", poolName),
					Suggestion: "Correct the address-pool annotation or create the referenced IPAddressPool.",
				})
			}
		}
		externalAddress := strings.Join(serviceExternalAddresses(service), ", ")
		if externalAddress == "" {
			externalAddress = "<pending>"
		}
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "loadbalancer-services",
			Resource: resource,
			Summary:  "External address: " + externalAddress,
			Detail: detailLines(
				"Cluster IP", service.Spec.ClusterIP,
				"Ports", servicePorts(service),
				"Address pool", poolName,
				"External traffic policy", string(service.Spec.ExternalTrafficPolicy),
			),
		})
		if len(service.Spec.Selector) == 0 {
			continue
		}
		ready, endpointErr := checker.readyEndpoints(ctx, service)
		if endpointErr != nil {
			report.Add(apiFailure("loadbalancer-services", "list endpoint slices for "+resource, endpointErr))
		} else if ready == 0 {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "loadbalancer-services",
				Resource:   resource,
				Summary:    "LoadBalancer service has no ready endpoints",
				Suggestion: "Check the service selector, backing pods, readiness probes, and target ports.",
			})
		}
	}
	report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "loadbalancer-services", Summary: fmt.Sprintf("Inspected %d LoadBalancer services", count)})
	return addresses
}

func serviceExternalAddresses(service corev1.Service) []string {
	addresses := make([]string, 0, len(service.Status.LoadBalancer.Ingress))
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			addresses = append(addresses, ingress.IP)
		} else if ingress.Hostname != "" {
			addresses = append(addresses, ingress.Hostname)
		}
	}
	return addresses
}

func servicePorts(service corev1.Service) string {
	ports := make([]string, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		value := fmt.Sprintf("%d/%s", port.Port, port.Protocol)
		if port.NodePort != 0 {
			value += fmt.Sprintf(" (node %d)", port.NodePort)
		}
		ports = append(ports, value)
	}
	return strings.Join(ports, ", ")
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

func (checker *Checker) checkWebhook(ctx context.Context, report *diagnostic.Report) {
	services, err := checker.clients.Kubernetes.CoreV1().Services(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("webhook", "list services", err))
		return
	}
	for _, service := range services.Items {
		if !strings.Contains(strings.ToLower(service.Name), "webhook") {
			continue
		}
		ready, endpointErr := checker.readyEndpoints(ctx, service)
		if endpointErr != nil {
			report.Add(apiFailure("webhook", "list endpoint slices", endpointErr))
			return
		}
		if ready == 0 {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "webhook",
				Resource:   diagnostic.Resource("service", service.Namespace, service.Name),
				Summary:    "MetalLB webhook service has no ready endpoints",
				Suggestion: "Check controller readiness and the webhook service selector.",
			})
		}
	}
}

func (checker *Checker) checkEvents(ctx context.Context, report *diagnostic.Report) {
	events, err := checker.clients.Kubernetes.CoreV1().Events(checker.options.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		report.Add(apiFailure("events", "list warning events", err))
		return
	}
	cutoff := time.Now().Add(-checker.options.EventSince)
	for _, event := range events.Items {
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
