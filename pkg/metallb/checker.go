package metallb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	addressPoolResource = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "ipaddresspools"}
	l2Resource          = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "l2advertisements"}
	bgpResource         = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "bgpadvertisements"}
	bgpPeerResource     = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta2", Resource: "bgppeers"}
)

type Options struct {
	Namespace  string
	EventSince time.Duration
	PendingFor time.Duration
}

type Checker struct {
	clients *kube.Clients
	options Options
}

func NewChecker(clients *kube.Clients, options Options) *Checker {
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
	pools := checker.checkConfiguration(ctx, &report)
	checker.checkLoadBalancerServices(ctx, &report, pools)
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
		for _, finding := range kube.PodFindings(pod, "pods") {
			report.Add(finding)
		}
	}
	if matched > 0 {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "pods", Summary: fmt.Sprintf("Inspected %d MetalLB pods", matched)})
	}
}

func (checker *Checker) checkConfiguration(ctx context.Context, report *diagnostic.Report) map[string]struct{} {
	pools := make(map[string]struct{})
	poolList, err := checker.clients.Dynamic.Resource(addressPoolResource).Namespace(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "configuration",
			Resource:   "ipaddresspools.metallb.io",
			Summary:    "Cannot read MetalLB IPAddressPool resources",
			Detail:     err.Error(),
			Suggestion: "Verify MetalLB CRDs are installed and RBAC allows listing IPAddressPools.",
		})
		return pools
	}
	for _, pool := range poolList.Items {
		pools[pool.GetName()] = struct{}{}
	}
	if len(pools) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "configuration",
			Resource:   "ipaddresspools.metallb.io",
			Summary:    "No IPAddressPool is configured",
			Suggestion: "Create an IPAddressPool containing addresses reachable on the local network.",
		})
	} else {
		names := make([]string, 0, len(pools))
		for name := range pools {
			names = append(names, name)
		}
		sort.Strings(names)
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "configuration", Resource: "ipaddresspools.metallb.io", Summary: fmt.Sprintf("Found %d address pools: %s", len(names), strings.Join(names, ", "))})
	}

	l2Count := checker.countOptionalResources(ctx, report, l2Resource)
	bgpCount := checker.countOptionalResources(ctx, report, bgpResource)
	peerCount := checker.countOptionalResources(ctx, report, bgpPeerResource)
	if l2Count == 0 && bgpCount == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "configuration",
			Summary:    "No L2Advertisement or BGPAdvertisement is configured",
			Suggestion: "Create an advertisement matching the address pool and intended network mode.",
		})
	}
	if bgpCount > 0 && peerCount == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "configuration",
			Resource:   "bgpadvertisements.metallb.io",
			Summary:    "BGP advertisements exist but no BGPPeer was found",
			Suggestion: "Configure at least one BGPPeer or verify peer resources in this namespace.",
		})
	}
	return pools
}

func (checker *Checker) countOptionalResources(ctx context.Context, report *diagnostic.Report, resource schema.GroupVersionResource) int {
	list, err := checker.clients.Dynamic.Resource(resource).Namespace(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			report.Add(diagnostic.Finding{Severity: diagnostic.SeverityWarning, Check: "configuration", Resource: resource.Resource + "." + resource.Group, Summary: "Cannot inspect optional MetalLB resources", Detail: err.Error()})
		}
		return 0
	}
	return len(list.Items)
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
