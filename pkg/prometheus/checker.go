package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	prometheusResource     = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheuses"}
	serviceMonitorResource = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}
	podMonitorResource     = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}
	ruleResource           = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}
)

type Options struct {
	Namespace     string
	EventSince    time.Duration
	PrometheusURL string
	HTTPTimeout   time.Duration
}

type Checker struct {
	clients    *kube.Clients
	options    Options
	httpClient *http.Client
}

func NewChecker(clients *kube.Clients, options Options) *Checker {
	return &Checker{
		clients: clients,
		options: options,
		httpClient: &http.Client{
			Timeout: options.HTTPTimeout,
		},
	}
}

func (checker *Checker) Run(ctx context.Context) (report diagnostic.Report) {
	report = diagnostic.Report{
		Target:    "prometheus",
		Namespace: checker.options.Namespace,
		StartedAt: time.Now(),
	}
	defer report.Complete()

	if _, err := checker.clients.Kubernetes.CoreV1().Namespaces().Get(ctx, checker.options.Namespace, metav1.GetOptions{}); err != nil {
		summary := "Cannot access Prometheus namespace"
		if apierrors.IsNotFound(err) {
			summary = "Prometheus namespace does not exist"
		}
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "namespace",
			Resource:   diagnostic.Resource("namespace", "", checker.options.Namespace),
			Summary:    summary,
			Detail:     err.Error(),
			Suggestion: "Verify Prometheus is installed and select its namespace with --namespace.",
		})
		return
	}

	checker.checkWorkloads(ctx, &report)
	pods := checker.checkPods(ctx, &report)
	checker.checkServices(ctx, &report)
	checker.checkStorage(ctx, &report, pods)
	checker.checkOperatorResources(ctx, &report)
	checker.checkEvents(ctx, &report)
	if checker.options.PrometheusURL != "" {
		checker.checkPrometheusAPI(ctx, &report)
	}
	return
}

func (checker *Checker) checkWorkloads(ctx context.Context, report *diagnostic.Report) {
	statefulSets, err := checker.clients.Kubernetes.AppsV1().StatefulSets(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("workloads", "list statefulsets", err))
		return
	}
	deployments, err := checker.clients.Kubernetes.AppsV1().Deployments(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("workloads", "list deployments", err))
		return
	}

	found := 0
	for _, statefulSet := range statefulSets.Items {
		if !isPrometheusComponent(statefulSet.Name, statefulSet.Labels) {
			continue
		}
		found++
		checker.evaluateStatefulSet(report, statefulSet)
	}
	for _, deployment := range deployments.Items {
		if !isPrometheusComponent(deployment.Name, deployment.Labels) {
			continue
		}
		found++
		checker.evaluateDeployment(report, deployment)
	}
	if found == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "workloads",
			Summary:    "No Prometheus server workload was found",
			Suggestion: "Verify the installation, namespace, and app.kubernetes.io/name labels.",
		})
	}
}

func (checker *Checker) evaluateStatefulSet(report *diagnostic.Report, statefulSet appsv1.StatefulSet) {
	resource := diagnostic.Resource("statefulset", statefulSet.Namespace, statefulSet.Name)
	desired := int32(1)
	if statefulSet.Spec.Replicas != nil {
		desired = *statefulSet.Spec.Replicas
	}
	finding := diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "workloads",
		Resource: resource,
		Summary:  fmt.Sprintf("Prometheus StatefulSet has %d/%d ready replicas", statefulSet.Status.ReadyReplicas, desired),
	}
	if desired == 0 || statefulSet.Status.ReadyReplicas < desired {
		finding.Severity = diagnostic.SeverityCritical
		finding.Suggestion = "Inspect pod logs, scheduling events, storage, and StatefulSet rollout status."
	}
	report.Add(finding)
}

func (checker *Checker) evaluateDeployment(report *diagnostic.Report, deployment appsv1.Deployment) {
	resource := diagnostic.Resource("deployment", deployment.Namespace, deployment.Name)
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	finding := diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "workloads",
		Resource: resource,
		Summary:  fmt.Sprintf("Prometheus Deployment has %d/%d available replicas", deployment.Status.AvailableReplicas, desired),
	}
	if desired == 0 || deployment.Status.AvailableReplicas < desired {
		finding.Severity = diagnostic.SeverityCritical
		finding.Suggestion = "Inspect pod logs, scheduling events, configuration mounts, and rollout status."
	}
	report.Add(finding)
}

func (checker *Checker) checkPods(ctx context.Context, report *diagnostic.Report) []corev1.Pod {
	podList, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("pods", "list pods", err))
		return nil
	}
	pods := make([]corev1.Pod, 0)
	for _, pod := range podList.Items {
		if !isPrometheusComponent(pod.Name, pod.Labels) {
			continue
		}
		pods = append(pods, pod)
		for _, finding := range kube.PodFindings(pod, "pods") {
			report.Add(finding)
		}
	}
	if len(pods) > 0 {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "pods", Summary: fmt.Sprintf("Inspected %d Prometheus pods", len(pods))})
	}
	return pods
}

func isPrometheusComponent(name string, labels map[string]string) bool {
	if !kube.MatchesComponent(name, labels, "prometheus") {
		return false
	}
	lowerName := strings.ToLower(name)
	for _, excluded := range []string{"operator", "adapter", "exporter", "pushgateway"} {
		if strings.Contains(lowerName, excluded) {
			return false
		}
	}
	component := strings.ToLower(labels["app.kubernetes.io/component"])
	return component != "operator" && component != "exporter"
}

func apiFailure(check, operation string, err error) diagnostic.Finding {
	return diagnostic.Finding{
		Severity:   diagnostic.SeverityWarning,
		Check:      check,
		Summary:    "Kubernetes API request failed: " + operation,
		Detail:     err.Error(),
		Suggestion: "Verify cluster connectivity and RBAC permissions.",
	}
}
