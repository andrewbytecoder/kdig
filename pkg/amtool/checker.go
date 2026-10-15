package amtool

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Options struct {
	Namespace       string
	StatefulSet     string
	Container       string
	AlertmanagerURL string
}

type Checker struct {
	clients *kube.Clients
	options Options
}

type podResult struct {
	pod             string
	alertCount      int
	alertsCollected bool
	alertDigest     string
	configOutput    string
}

func NewChecker(clients *kube.Clients, options Options) *Checker {
	if options.Namespace == "" {
		options.Namespace = "monitoring"
	}
	if options.StatefulSet == "" {
		options.StatefulSet = "alertmanager-main"
	}
	if options.Container == "" {
		options.Container = "alertmanager"
	}
	if options.AlertmanagerURL == "" {
		options.AlertmanagerURL = "http://localhost:9093"
	}
	return &Checker{clients: clients, options: options}
}

func (checker *Checker) Run(ctx context.Context) (report diagnostic.Report) {
	report = diagnostic.Report{
		Target:    "amtool",
		Namespace: checker.options.Namespace,
		StartedAt: time.Now(),
	}
	defer report.Complete()

	statefulSet, err := checker.clients.Kubernetes.AppsV1().StatefulSets(checker.options.Namespace).Get(ctx, checker.options.StatefulSet, metav1.GetOptions{})
	if err != nil {
		summary := "Cannot read Alertmanager StatefulSet"
		if apierrors.IsNotFound(err) {
			summary = "Alertmanager StatefulSet was not found"
		}
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "statefulset",
			Resource:   diagnostic.Resource("statefulset", checker.options.Namespace, checker.options.StatefulSet),
			Summary:    summary,
			Detail:     err.Error(),
			Suggestion: "Select the correct namespace and StatefulSet with --namespace and --statefulset.",
		})
		return
	}

	checker.checkStatefulSet(&report, *statefulSet)
	pods := checker.findPods(ctx, &report, *statefulSet)
	if len(pods) == 0 {
		return
	}
	if checker.clients.PodExec == nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pod-exec",
			Summary:    "Pod exec client is not available",
			Suggestion: "Verify the Kubernetes client and pods/exec RBAC permissions.",
		})
		return
	}

	results := make([]podResult, 0, len(pods))
	for _, pod := range pods {
		checker.checkPod(&report, pod)
		result := checker.collectFromPod(ctx, &report, pod)
		results = append(results, result)
	}
	checker.compareReplicas(&report, results)
	return
}

func (checker *Checker) checkStatefulSet(report *diagnostic.Report, statefulSet appsv1.StatefulSet) {
	desired := int32(1)
	if statefulSet.Spec.Replicas != nil {
		desired = *statefulSet.Spec.Replicas
	}
	finding := diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "statefulset",
		Resource: diagnostic.Resource("statefulset", statefulSet.Namespace, statefulSet.Name),
		Summary:  fmt.Sprintf("Alertmanager StatefulSet has %d/%d ready replicas", statefulSet.Status.ReadyReplicas, desired),
	}
	if desired == 0 || statefulSet.Status.ReadyReplicas < desired {
		finding.Severity = diagnostic.SeverityCritical
		finding.Suggestion = "Inspect Alertmanager pod health, storage, scheduling events, and rollout status."
	}
	report.Add(finding)
}

func (checker *Checker) findPods(ctx context.Context, report *diagnostic.Report, statefulSet appsv1.StatefulSet) []corev1.Pod {
	selector := labels.Everything()
	if statefulSet.Spec.Selector != nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(statefulSet.Spec.Selector)
		if err != nil {
			report.Add(diagnostic.Finding{
				Severity: diagnostic.SeverityCritical,
				Check:    "pods",
				Summary:  "Alertmanager StatefulSet has an invalid pod selector",
				Detail:   err.Error(),
			})
			return nil
		}
	}
	podList, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		report.Add(apiFailure("pods", "list Alertmanager pods", err))
		return nil
	}

	pods := make([]corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if ownedByStatefulSet(pod, statefulSet.Name) || strings.HasPrefix(pod.Name, statefulSet.Name+"-") {
			pods = append(pods, pod)
		}
	}
	sort.Slice(pods, func(left, right int) bool {
		return pods[left].Name < pods[right].Name
	})
	desired := int32(1)
	if statefulSet.Spec.Replicas != nil {
		desired = *statefulSet.Spec.Replicas
	}
	foundNames := make(map[string]struct{}, len(pods))
	for _, pod := range pods {
		foundNames[pod.Name] = struct{}{}
	}
	missing := make([]string, 0)
	for ordinal := int32(0); ordinal < desired; ordinal++ {
		name := fmt.Sprintf("%s-%d", statefulSet.Name, ordinal)
		if _, exists := foundNames[name]; !exists {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pods",
			Resource:   diagnostic.Resource("statefulset", statefulSet.Namespace, statefulSet.Name),
			Summary:    fmt.Sprintf("Found %d/%d expected Alertmanager pods", len(pods), desired),
			Detail:     "Missing pods: " + strings.Join(missing, ", "),
			Suggestion: "Inspect StatefulSet events, scheduling, PVCs, and pod creation failures.",
		})
	}
	if len(pods) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pods",
			Summary:    "No Alertmanager pods were found for the StatefulSet",
			Suggestion: "Verify the StatefulSet selector and pod ownership.",
		})
	}
	return pods
}

func (checker *Checker) checkPod(report *diagnostic.Report, pod corev1.Pod) {
	readyContainers := 0
	for _, status := range pod.Status.ContainerStatuses {
		if status.Ready {
			readyContainers++
		}
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "pods",
		Resource: diagnostic.Resource("pod", pod.Namespace, pod.Name),
		Summary:  fmt.Sprintf("Phase %s, ready containers %d/%d", pod.Status.Phase, readyContainers, len(pod.Spec.Containers)),
		Detail:   fmt.Sprintf("Node: %s\nPod IP: %s", valueOrDash(pod.Spec.NodeName), valueOrDash(pod.Status.PodIP)),
	})
	for _, finding := range kube.PodFindings(pod, "pods") {
		report.Add(finding)
	}
	if !hasContainer(pod, checker.options.Container) {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pods",
			Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name),
			Summary:    fmt.Sprintf("Container %q was not found", checker.options.Container),
			Suggestion: "Set --container to the container that includes amtool.",
		})
	}
}

func ownedByStatefulSet(pod corev1.Pod, name string) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "StatefulSet" && owner.Name == name {
			return true
		}
	}
	return false
}

func hasContainer(pod corev1.Pod, name string) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == name {
			return true
		}
	}
	return false
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
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
