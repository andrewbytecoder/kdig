package metallb

import (
	"context"
	"fmt"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	crdResource         = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	addressPoolResource = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "ipaddresspools"}
	l2Resource          = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "l2advertisements"}
	bgpResource         = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "bgpadvertisements"}
	bgpPeerResource     = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta2", Resource: "bgppeers"}
)

type Options struct {
	Namespace    string
	EventSince   time.Duration
	PendingFor   time.Duration
	FRRContainer string
}

type Checker struct {
	clients *kube.Clients
	options Options
}

func NewChecker(clients *kube.Clients, options Options) *Checker {
	if options.Namespace == "" {
		options.Namespace = "metallb-system"
	}
	if options.FRRContainer == "" {
		options.FRRContainer = "frr"
	}
	return &Checker{clients: clients, options: options}
}

func (checker *Checker) Run(ctx context.Context) (report diagnostic.Report) {
	report = diagnostic.Report{
		Target:    "metallb",
		Namespace: checker.options.Namespace,
		StartedAt: time.Now(),
	}
	defer report.Complete()

	if _, err := checker.clients.Kubernetes.CoreV1().Namespaces().Get(ctx, checker.options.Namespace, metav1.GetOptions{}); err != nil {
		summary := "Cannot access MetalLB namespace"
		if apierrors.IsNotFound(err) {
			summary = "MetalLB namespace does not exist"
		}
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "namespace",
			Resource:   diagnostic.Resource("namespace", "", checker.options.Namespace),
			Summary:    summary,
			Detail:     err.Error(),
			Suggestion: "Verify MetalLB is installed and select its namespace with --namespace.",
		})
		return
	}

	checker.checkController(ctx, &report)
	checker.checkSpeaker(ctx, &report)
	checker.checkPods(ctx, &report)
	configuration := checker.checkConfiguration(ctx, &report)
	serviceAddresses := checker.checkLoadBalancerServices(ctx, &report, configuration.pools)
	if configuration.bgpEnabled {
		checker.checkBGPSessions(ctx, &report)
		checker.addNetworkSuggestions(&report, serviceAddresses, configuration.peerAddresses)
	}
	checker.checkWebhook(ctx, &report)
	checker.checkEvents(ctx, &report)
	return
}

func (checker *Checker) checkController(ctx context.Context, report *diagnostic.Report) {
	deployments, err := checker.clients.Kubernetes.AppsV1().Deployments(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("controller", "list deployments", err))
		return
	}
	matched := make([]appsv1.Deployment, 0)
	for _, deployment := range deployments.Items {
		if kube.MatchesComponent(deployment.Name, deployment.Labels, "controller") {
			matched = append(matched, deployment)
		}
	}
	if len(matched) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "controller",
			Summary:    "MetalLB controller Deployment was not found",
			Suggestion: "Verify the MetalLB manifests or Helm release and the selected namespace.",
		})
		return
	}
	for _, deployment := range matched {
		resource := diagnostic.Resource("deployment", deployment.Namespace, deployment.Name)
		desired := int32(1)
		if deployment.Spec.Replicas != nil {
			desired = *deployment.Spec.Replicas
		}
		finding := diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "controller",
			Resource: resource,
			Summary:  fmt.Sprintf("Controller has %d/%d available replicas", deployment.Status.AvailableReplicas, desired),
		}
		if desired == 0 || deployment.Status.AvailableReplicas < desired {
			finding.Severity = diagnostic.SeverityCritical
			finding.Suggestion = "Inspect controller pod logs, scheduling events, and deployment rollout status."
		}
		report.Add(finding)
	}
}

func (checker *Checker) checkSpeaker(ctx context.Context, report *diagnostic.Report) {
	daemonSets, err := checker.clients.Kubernetes.AppsV1().DaemonSets(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("speaker", "list daemonsets", err))
		return
	}
	matched := make([]appsv1.DaemonSet, 0)
	for _, daemonSet := range daemonSets.Items {
		if kube.MatchesComponent(daemonSet.Name, daemonSet.Labels, "speaker") {
			matched = append(matched, daemonSet)
		}
	}
	if len(matched) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "speaker",
			Summary:    "MetalLB speaker DaemonSet was not found",
			Suggestion: "Verify the MetalLB installation and node selectors or tolerations.",
		})
		return
	}
	for _, daemonSet := range matched {
		resource := diagnostic.Resource("daemonset", daemonSet.Namespace, daemonSet.Name)
		desired := daemonSet.Status.DesiredNumberScheduled
		available := daemonSet.Status.NumberAvailable
		finding := diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "speaker",
			Resource: resource,
			Summary:  fmt.Sprintf("Speaker has %d/%d available pods", available, desired),
		}
		if desired == 0 || available < desired {
			finding.Severity = diagnostic.SeverityCritical
			finding.Suggestion = "Inspect speaker pod events, host network access, node selectors, and tolerations."
		}
		report.Add(finding)
	}
}

func (checker *Checker) checkPods(ctx context.Context, report *diagnostic.Report) {
	pods, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("pods", "list pods", err))
		return
	}
	matched := 0
	for _, pod := range pods.Items {
		if !kube.MatchesComponent(pod.Name, pod.Labels, "controller", "speaker", "metallb") {
			continue
		}
		matched++
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
			Detail: detailLines(
				"Node", pod.Spec.NodeName,
				"Pod IP", pod.Status.PodIP,
				"Host IP", pod.Status.HostIP,
			),
		})
		for _, finding := range kube.PodFindings(pod, "pods") {
			report.Add(finding)
		}
	}
	if matched > 0 {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "pods", Summary: fmt.Sprintf("Inspected %d MetalLB pods", matched)})
	}
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
