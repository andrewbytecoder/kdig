package podinfo

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	Namespace           string
	Pod                 string
	Username            string
	Password            string
	IdentityFile        string
	KnownHostsFile      string
	SSHPort             int
	InsecureSkipHostKey bool
	Timeout             time.Duration
}

type RemoteRunner interface {
	Run(ctx context.Context, address string, command string) (string, error)
}

type Checker struct {
	clients *kube.Clients
	options Options
	runner  RemoteRunner
}

func NewChecker(clients *kube.Clients, options Options, runner RemoteRunner) *Checker {
	if options.Namespace == "" {
		options.Namespace = corev1.NamespaceDefault
	}
	if options.Username == "" {
		options.Username = "root"
	}
	if options.SSHPort == 0 {
		options.SSHPort = 22
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	if runner == nil {
		runner = NewSSHRunner(SSHOptions{
			Username:            options.Username,
			Password:            options.Password,
			IdentityFile:        options.IdentityFile,
			KnownHostsFile:      options.KnownHostsFile,
			InsecureSkipHostKey: options.InsecureSkipHostKey,
			Timeout:             options.Timeout,
		})
	}
	return &Checker{clients: clients, options: options, runner: runner}
}

func (checker *Checker) Run(ctx context.Context) (report diagnostic.Report) {
	report = diagnostic.Report{
		Target:    "podinfo",
		Namespace: checker.options.Namespace,
		StartedAt: time.Now(),
	}
	defer report.Complete()

	podNames, ok := checker.targetPodNames(ctx, &report)
	if !ok {
		return
	}
	for _, podName := range podNames {
		checker.inspectPod(ctx, &report, podName)
	}
	return
}

func (checker *Checker) targetPodNames(ctx context.Context, report *diagnostic.Report) ([]string, bool) {
	if checker.options.Pod != "" {
		return []string{checker.options.Pod}, true
	}
	podList, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pods",
			Resource:   diagnostic.Resource("namespace", "", checker.options.Namespace),
			Summary:    "Cannot list Pods in namespace",
			Detail:     err.Error(),
			Suggestion: "Verify the namespace, cluster connectivity, and RBAC permissions.",
		})
		return nil, false
	}
	podNames := make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		podNames = append(podNames, pod.Name)
	}
	sort.Strings(podNames)
	if len(podNames) == 0 {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityWarning,
			Check:    "pods",
			Resource: diagnostic.Resource("namespace", "", checker.options.Namespace),
			Summary:  "No Pods were found in namespace",
		})
		return nil, false
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "pods",
		Resource: diagnostic.Resource("namespace", "", checker.options.Namespace),
		Summary:  fmt.Sprintf("Inspecting %d Pods in namespace", len(podNames)),
		Detail:   strings.Join(podNames, ", "),
	})
	return podNames, true
}

func (checker *Checker) inspectPod(ctx context.Context, report *diagnostic.Report, podName string) {
	pod, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		summary := "Cannot read Pod"
		if apierrors.IsNotFound(err) {
			summary = "Pod was not found"
		}
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "pod",
			Resource:   diagnostic.Resource("pod", checker.options.Namespace, podName),
			Summary:    summary,
			Detail:     err.Error(),
			Suggestion: "Verify the pod name and namespace.",
		})
		return
	}
	if pod.Spec.NodeName == "" {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "scheduling",
			Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name),
			Summary:    "Pod is not assigned to a node",
			Suggestion: "Inspect pod scheduling events before querying its network namespace.",
		})
		return
	}

	node, err := checker.clients.Kubernetes.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		report.Add(apiFailure("node", "get node "+pod.Spec.NodeName, err))
		return
	}
	nodeIP := preferredNodeIP(*node)
	if nodeIP == "" {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "node",
			Resource:   diagnostic.Resource("node", "", node.Name),
			Summary:    "Node has no InternalIP or ExternalIP address",
			Suggestion: "Inspect node status addresses or provide a reachable node address.",
		})
		return
	}

	checker.addKubernetesInfo(report, *pod, *node, nodeIP)
	address := net.JoinHostPort(nodeIP, strconv.Itoa(checker.options.SSHPort))
	version, err := checker.runner.Run(ctx, address, "crictl --version")
	if err != nil {
		report.Add(remoteFailure("ssh", diagnostic.Resource("node", "", node.Name), "Cannot execute crictl on node", err))
		return
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "runtime",
		Resource: diagnostic.Resource("node", "", node.Name),
		Summary:  firstLine(version),
		Detail:   fmt.Sprintf("SSH: %s@%s", checker.options.Username, address),
	})

	containersOutput, err := checker.runner.Run(ctx, address, "crictl ps -a -o json")
	if err != nil {
		report.Add(remoteFailure("runtime", diagnostic.Resource("node", "", node.Name), "Cannot list CRI containers", err))
		return
	}
	containers, err := selectPodContainers(containersOutput, *pod)
	if err != nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "runtime",
			Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name),
			Summary:    "Cannot parse crictl container output",
			Detail:     err.Error(),
			Suggestion: "Verify crictl supports JSON output and is configured for the node's CRI endpoint.",
		})
		return
	}
	if len(containers) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "runtime",
			Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name),
			Summary:    "No CRI containers matched the Pod",
			Suggestion: "Check the CRI endpoint, container labels, and whether the pod was recently recreated.",
		})
		return
	}

	checker.inspectContainers(ctx, report, address, *pod, containers)
}

func (checker *Checker) addKubernetesInfo(report *diagnostic.Report, pod corev1.Pod, node corev1.Node, nodeIP string) {
	detail := []string{
		"Node: " + node.Name,
		"Node IP: " + nodeIP,
		"Pod IP: " + valueOrDash(pod.Status.PodIP),
		"Host network: " + strconv.FormatBool(pod.Spec.HostNetwork),
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "pod",
		Resource: diagnostic.Resource("pod", pod.Namespace, pod.Name),
		Summary:  fmt.Sprintf("Pod phase %s on node %s", pod.Status.Phase, node.Name),
		Detail:   strings.Join(detail, "\n"),
	})

	containerIDs := currentContainerIDs(pod)
	for _, container := range podContainers(pod) {
		containerID := valueOrDash(containerIDs[container.name])
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "containers",
			Resource: diagnostic.Resource("pod", pod.Namespace, pod.Name) + "/" + container.name,
			Summary:  fmt.Sprintf("%s container %s", container.kind, container.name),
			Detail:   "Kubernetes container ID: " + containerID,
		})
	}
}

func (checker *Checker) inspectContainers(
	ctx context.Context,
	report *diagnostic.Report,
	address string,
	pod corev1.Pod,
	containers []runtimeContainer,
) {
	namespaces := make(map[string][]string)
	foundNames := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		foundNames[container.Metadata.Name] = struct{}{}
		output, err := checker.runner.Run(ctx, address, "crictl inspect "+shellQuote(container.ID))
		if err != nil {
			report.Add(remoteFailure(
				"inspect",
				containerResource(pod, container),
				"Cannot inspect CRI container "+container.Metadata.Name,
				err,
			))
			continue
		}
		inspection, err := parseInspection(output)
		if err != nil {
			report.Add(diagnostic.Finding{
				Severity: diagnostic.SeverityWarning,
				Check:    "inspect",
				Resource: containerResource(pod, container),
				Summary:  "Cannot parse crictl inspect output",
				Detail:   err.Error(),
			})
			continue
		}
		pid := inspection.networkPID()
		if pid <= 0 {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "network-namespace",
				Resource:   containerResource(pod, container),
				Summary:    "Container has no usable network namespace PID",
				Suggestion: "Verify the container is running and inspect the runtime output manually.",
			})
			continue
		}

		namespaceID, namespaceErr := checker.runner.Run(ctx, address, fmt.Sprintf("readlink /proc/%d/ns/net", pid))
		namespaceID = strings.TrimSpace(namespaceID)
		if namespaceErr != nil {
			namespaceID = "unknown"
		}
		namespaces[namespaceID] = append(namespaces[namespaceID], container.Metadata.Name)
		detail := []string{
			"CRI container ID: " + container.ID,
			"CRI state: " + valueOrDash(container.State),
			"Network PID: " + strconv.Itoa(pid),
			"Network namespace: " + namespaceID,
			fmt.Sprintf("Enter namespace: nsenter -t %d -n", pid),
		}
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "network-namespace",
			Resource: containerResource(pod, container),
			Summary:  fmt.Sprintf("Container %s uses network PID %d", container.Metadata.Name, pid),
			Detail:   strings.Join(detail, "\n"),
		})
	}

	for _, container := range podContainers(pod) {
		if _, exists := foundNames[container.name]; !exists {
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "runtime",
				Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name) + "/" + container.name,
				Summary:    "Kubernetes container was not found in crictl output",
				Suggestion: "Check whether the container is waiting, terminated, or the CRI endpoint is incorrect.",
			})
		}
	}
	if len(namespaces) > 1 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "network-namespace",
			Resource:   diagnostic.Resource("pod", pod.Namespace, pod.Name),
			Summary:    "Pod containers do not resolve to one network namespace",
			Detail:     formatNamespaceGroups(namespaces),
			Suggestion: "Re-run crictl inspect and readlink manually; terminated containers may reference stale namespaces.",
		})
	}
}

type namedContainer struct {
	name string
	kind string
}

func podContainers(pod corev1.Pod) []namedContainer {
	containers := make([]namedContainer, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	for _, container := range pod.Spec.InitContainers {
		containers = append(containers, namedContainer{name: container.Name, kind: "init"})
	}
	for _, container := range pod.Spec.Containers {
		containers = append(containers, namedContainer{name: container.Name, kind: "app"})
	}
	for _, container := range pod.Spec.EphemeralContainers {
		containers = append(containers, namedContainer{name: container.Name, kind: "ephemeral"})
	}
	return containers
}

func currentContainerIDs(pod corev1.Pod) map[string]string {
	result := make(map[string]string)
	statuses := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, status := range statuses {
		result[status.Name] = status.ContainerID
	}
	return result
}

func preferredNodeIP(node corev1.Node) string {
	for _, addressType := range []corev1.NodeAddressType{corev1.NodeInternalIP, corev1.NodeExternalIP} {
		for _, address := range node.Status.Addresses {
			if address.Type == addressType && address.Address != "" {
				return address.Address
			}
		}
	}
	return ""
}

func containerResource(pod corev1.Pod, container runtimeContainer) string {
	return diagnostic.Resource("pod", pod.Namespace, pod.Name) + "/" + container.Metadata.Name
}

func formatNamespaceGroups(groups map[string][]string) string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		sort.Strings(groups[key])
		lines = append(lines, key+": "+strings.Join(groups[key], ", "))
	}
	return strings.Join(lines, "\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func firstLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "crictl is available"
	}
	return lines[0]
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

func remoteFailure(check, resource, summary string, err error) diagnostic.Finding {
	return diagnostic.Finding{
		Severity:   diagnostic.SeverityCritical,
		Check:      check,
		Resource:   resource,
		Summary:    summary,
		Detail:     err.Error(),
		Suggestion: "Verify SSH connectivity, authentication, known_hosts, node permissions, and crictl configuration.",
	}
}
