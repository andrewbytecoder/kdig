package metallb

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type bgpNeighbor struct {
	address     string
	state       string
	established bool
}

func (checker *Checker) checkBGPSessions(ctx context.Context, report *diagnostic.Report) {
	podList, err := checker.clients.Kubernetes.CoreV1().Pods(checker.options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(apiFailure("bgp-sessions", "list speaker pods", err))
		return
	}

	speakers := make([]corev1.Pod, 0)
	for _, pod := range podList.Items {
		if isSpeakerPod(pod) {
			speakers = append(speakers, pod)
		}
	}
	if len(speakers) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "bgp-sessions",
			Summary:    "No MetalLB speaker pods were found",
			Suggestion: "Verify the speaker DaemonSet, pod names, and app/component labels.",
		})
		return
	}
	if checker.clients.PodExec == nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "bgp-sessions",
			Summary:    "Pod exec client is not available",
			Suggestion: "Provide a Kubernetes client capable of creating pods/exec requests.",
		})
		return
	}

	sort.Slice(speakers, func(left, right int) bool {
		return speakers[left].Name < speakers[right].Name
	})
	for _, pod := range speakers {
		checker.checkSpeakerBGP(ctx, report, pod)
	}
}

func (checker *Checker) checkSpeakerBGP(ctx context.Context, report *diagnostic.Report, pod corev1.Pod) {
	resource := diagnostic.Resource("pod", pod.Namespace, pod.Name)
	if !hasContainer(pod, checker.options.FRRContainer) {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "bgp-sessions",
			Resource:   resource,
			Summary:    fmt.Sprintf("FRR container %q was not found on speaker pod", checker.options.FRRContainer),
			Detail:     "Node: " + valueOrDash(pod.Spec.NodeName),
			Suggestion: "Set --frr-container to the deployed FRR container name or verify MetalLB FRR mode is enabled.",
		})
		return
	}

	summary, stderr, err := checker.execVtysh(ctx, pod.Name, "show bgp summary")
	if err != nil {
		report.Add(execFailure("bgp-sessions", resource, "BGP summary", stderr, err))
		return
	}
	neighbors := parseBGPSummary(summary)
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "bgp-sessions",
		Resource: resource,
		Summary:  fmt.Sprintf("Collected BGP summary on node %s; found %d neighbors", valueOrDash(pod.Spec.NodeName), len(neighbors)),
		Detail:   truncateOutput(summary),
	})
	if len(neighbors) == 0 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "bgp-sessions",
			Resource:   resource,
			Summary:    "No BGP neighbors were present in the FRR summary",
			Suggestion: "Check BGPPeer node selectors, peer address reachability, ASN values, and FRR configuration.",
		})
	}
	for _, neighbor := range neighbors {
		severity := diagnostic.SeverityCritical
		suggestion := "Check TCP/179 connectivity, peer and local ASN values, router configuration, and BGP authentication."
		if neighbor.established {
			severity = diagnostic.SeverityInfo
			suggestion = ""
		}
		report.Add(diagnostic.Finding{
			Severity:   severity,
			Check:      "bgp-neighbors",
			Resource:   pod.Name + "/" + neighbor.address,
			Summary:    "BGP neighbor state: " + neighbor.state,
			Detail:     "Node: " + valueOrDash(pod.Spec.NodeName),
			Suggestion: suggestion,
		})
		checker.checkAdvertisedRoutes(ctx, report, pod, neighbor.address)
	}

	routes, routeStderr, routeErr := checker.execVtysh(ctx, pod.Name, "show bgp ipv4 unicast")
	if routeErr != nil {
		report.Add(execFailure("bgp-routes", resource, "IPv4 unicast BGP routing table", routeStderr, routeErr))
		return
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "bgp-routes",
		Resource: resource,
		Summary:  "Collected IPv4 unicast BGP routing table",
		Detail:   truncateOutput(routes),
	})
}

func (checker *Checker) checkAdvertisedRoutes(ctx context.Context, report *diagnostic.Report, pod corev1.Pod, neighbor string) {
	output, stderr, err := checker.execVtysh(ctx, pod.Name, "show bgp neighbors "+neighbor+" advertised-routes")
	resource := pod.Name + "/" + neighbor
	if err != nil {
		report.Add(execFailure("advertised-routes", resource, "advertised routes", stderr, err))
		return
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "advertised-routes",
		Resource: resource,
		Summary:  "Collected routes advertised to BGP neighbor",
		Detail:   truncateOutput(output),
	})
}

func (checker *Checker) execVtysh(ctx context.Context, pod string, command string) (string, string, error) {
	return checker.clients.PodExec.Exec(
		ctx,
		checker.options.Namespace,
		pod,
		checker.options.FRRContainer,
		[]string{"vtysh", "-c", command},
	)
}

func (checker *Checker) addNetworkSuggestions(report *diagnostic.Report, serviceAddresses, peerAddresses []string) {
	for _, address := range uniqueStrings(serviceAddresses) {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "network-guidance",
			Resource: address,
			Summary:  "Suggested external address checks",
			Detail: strings.Join([]string{
				"Node capture: sudo tcpdump -i any host " + address + " -n",
				"Router route: show ip route " + address,
				"Connectivity: ping " + address,
				"Verify ARP for IPv4 or neighbor discovery for IPv6.",
			}, "\n"),
		})
	}
	for _, address := range uniqueStrings(peerAddresses) {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "network-guidance",
			Resource: address,
			Summary:  "Suggested BGP transport check",
			Detail:   "Node capture: sudo tcpdump -i any host " + address + " and port 179 -n",
		})
	}
}

func parseBGPSummary(output string) []bgpNeighbor {
	neighbors := make([]bgpNeighbor, 0)
	stateIndex := -1
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "Neighbor") {
			for index, field := range fields {
				if strings.HasPrefix(strings.ToLower(field), "state/") {
					stateIndex = index
					break
				}
			}
			continue
		}
		if net.ParseIP(strings.Trim(fields[0], "[]")) == nil {
			continue
		}
		state := "unknown"
		if stateIndex >= 0 && stateIndex < len(fields) {
			state = fields[stateIndex]
		} else {
			state = findBGPState(fields)
		}
		neighbors = append(neighbors, bgpNeighbor{
			address:     strings.Trim(fields[0], "[]"),
			state:       state,
			established: isEstablishedState(state),
		})
	}
	return neighbors
}

func findBGPState(fields []string) string {
	for _, field := range fields {
		switch strings.ToLower(field) {
		case "idle", "active", "connect", "opensent", "openconfirm", "established":
			return field
		}
	}
	return "unknown"
}

func isEstablishedState(state string) bool {
	if strings.EqualFold(state, "established") {
		return true
	}
	_, err := strconv.ParseUint(strings.TrimSpace(state), 10, 64)
	return err == nil
}

func isSpeakerPod(pod corev1.Pod) bool {
	if strings.HasPrefix(strings.ToLower(pod.Name), "metallb-speaker-") {
		return true
	}
	return kube.MatchesComponent(pod.Name, pod.Labels, "speaker")
}

func hasContainer(pod corev1.Pod, name string) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == name {
			return true
		}
	}
	return false
}

func execFailure(check, resource, operation, stderr string, err error) diagnostic.Finding {
	detail := strings.TrimSpace(stderr)
	if detail != "" {
		detail += "\n"
	}
	detail += err.Error()
	return diagnostic.Finding{
		Severity:   diagnostic.SeverityWarning,
		Check:      check,
		Resource:   resource,
		Summary:    "Cannot collect " + operation,
		Detail:     detail,
		Suggestion: "Verify pods/exec RBAC permissions, the FRR container name, and vtysh availability.",
	}
}

func truncateOutput(output string) string {
	const maxLength = 12000
	trimmed := strings.TrimSpace(output)
	runes := []rune(trimmed)
	if len(runes) <= maxLength {
		return trimmed
	}
	return string(runes[:maxLength]) + "\n... output truncated"
}

func uniqueStrings(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
