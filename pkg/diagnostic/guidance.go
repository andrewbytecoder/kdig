package diagnostic

import "strings"

type resourceReference struct {
	kind      string
	namespace string
	name      string
}

func enrichFinding(target string, namespace string, finding Finding) Finding {
	check := baseCheck(finding.Check)
	if finding.Describe == "" {
		finding.Describe = describeCheck(target, check)
	}
	if len(finding.Verify) == 0 {
		commands := commandsForResource(parseResource(finding.Resource), namespace)
		commands = append(commands, commandsForCheck(target, check, namespace, finding)...)
		if len(commands) == 0 {
			commands = fallbackCommands(target, namespace)
		}
		finding.Verify = uniqueCommands(commands)
	}
	return finding
}

func fallbackCommands(target string, namespace string) []string {
	switch target {
	case "metallb":
		return []string{"kubectl get all -n " + namespace + " -o wide"}
	case "prometheus":
		return []string{"kubectl get pods,service,statefulset,deployment,pvc -n " + namespace + " -o wide"}
	case "amtool":
		return []string{"kubectl get statefulset,pods -n " + namespace + " -o wide | grep alertmanager"}
	case "podinfo", "netcap":
		return []string{"kubectl get pods -n " + namespace + " -o wide"}
	default:
		if namespace != "" {
			return []string{"kubectl get pods -n " + namespace + " -o wide"}
		}
		return []string{"kubectl cluster-info"}
	}
}

func describeCheck(target string, check string) string {
	descriptions := map[string]map[string]string{
		"metallb": {
			"namespace":             "Verifies that the MetalLB namespace exists and is accessible.",
			"controller":            "Checks the MetalLB controller Deployment and its available replicas.",
			"speaker":               "Checks the MetalLB speaker DaemonSet coverage and availability on cluster nodes.",
			"pods":                  "Shows MetalLB Pod placement, readiness, container state, and restart problems.",
			"configuration":         "Checks whether MetalLB has an address advertisement mode configured.",
			"crds":                  "Verifies that MetalLB CustomResourceDefinitions are installed.",
			"address-pools":         "Shows configured MetalLB IP address pools and allocation status.",
			"bgp-configuration":     "Shows MetalLB BGP peers and BGP advertisement configuration.",
			"l2-configuration":      "Shows MetalLB layer-2 advertisement configuration.",
			"bgp-sessions":          "Collects the FRR BGP summary from a MetalLB speaker Pod.",
			"bgp-neighbors":         "Reports whether an FRR BGP neighbor session is established.",
			"bgp-routes":            "Shows the IPv4 unicast BGP routing table inside the speaker FRR container.",
			"advertised-routes":     "Shows routes advertised by a speaker to a specific BGP neighbor.",
			"network-guidance":      "Provides node and router commands for validating network reachability.",
			"loadbalancer-services": "Checks LoadBalancer address assignment and ready backend endpoints.",
			"webhook":               "Checks whether the MetalLB admission webhook Service has ready endpoints.",
			"events":                "Shows recent Kubernetes warning events in the MetalLB namespace.",
		},
		"prometheus": {
			"namespace":          "Verifies that the Prometheus namespace exists and is accessible.",
			"workloads":          "Checks Prometheus StatefulSet or Deployment replica availability.",
			"pods":               "Checks Prometheus Pod phases, readiness, container failures, and restarts.",
			"services":           "Checks Prometheus Services and their ready EndpointSlices.",
			"storage":            "Checks PersistentVolumeClaims mounted by Prometheus Pods.",
			"operator-resources": "Lists Prometheus Operator custom resources used for discovery and rules.",
			"events":             "Shows recent Kubernetes warning events related to Prometheus.",
			"prometheus-api":     "Checks Prometheus HTTP readiness and API connectivity.",
			"scrape-targets":     "Checks active Prometheus scrape targets and reports targets that are down.",
			"rules":              "Checks Prometheus recording and alerting rule health.",
		},
		"amtool": {
			"statefulset":         "Checks the Alertmanager StatefulSet desired and ready replicas.",
			"pods":                "Shows Alertmanager Pod discovery, placement, and readiness.",
			"pod-exec":            "Checks whether the diagnostic can execute amtool inside Alertmanager Pods.",
			"amtool-version":      "Shows the amtool version available inside an Alertmanager Pod.",
			"alerts":              "Summarizes active Alertmanager alerts by name and severity.",
			"alerts-extended":     "Shows extended Alertmanager alert labels, annotations, timestamps, and state.",
			"configuration":       "Shows the currently loaded Alertmanager configuration with sensitive values redacted.",
			"routes":              "Shows the Alertmanager notification routing tree.",
			"silences":            "Summarizes Alertmanager silences and their current state.",
			"cluster":             "Shows Alertmanager HA cluster peers and state.",
			"replica-consistency": "Compares alerts and loaded configuration across Alertmanager replicas.",
		},
		"podinfo": {
			"pods":              "Lists the Pods selected for node-side runtime inspection.",
			"pod":               "Shows Kubernetes Pod placement, Pod IP, phase, and host-network mode.",
			"scheduling":        "Checks whether Kubernetes assigned the Pod to a node.",
			"node":              "Shows the node selected by Kubernetes and the node address used for SSH.",
			"containers":        "Lists app, init, and ephemeral containers declared by the Pod.",
			"ssh":               "Checks SSH access to the Kubernetes node.",
			"runtime":           "Maps Kubernetes containers to CRI containers using crictl.",
			"inspect":           "Reads detailed CRI runtime information for a container.",
			"network-namespace": "Shows the Linux PID and network namespace shared by Pod containers.",
		},
		"netcap": {
			"capture-options": "Validates packet capture protocol, address, port, interface, and duration options.",
			"local-output":    "Checks and prepares the local pcap output path.",
			"network-target":  "Resolves the Pod node, CRI container, and Linux network namespace PID.",
			"progress":        "Reports the resolved tcpdump command before packet capture starts.",
			"capture":         "Runs tcpdump inside the Pod network namespace and streams the pcap to this machine.",
		},
	}
	if targetDescriptions, ok := descriptions[target]; ok {
		if description := targetDescriptions[check]; description != "" {
			return description
		}
	}
	generic := map[string]string{
		"namespace": "Checks whether the Kubernetes namespace exists and is accessible.",
		"pods":      "Shows Kubernetes Pod health and runtime state.",
		"events":    "Shows recent Kubernetes warning events relevant to this component.",
	}
	if description := generic[check]; description != "" {
		return description
	}
	return "Reports the observed state for this diagnostic check."
}

func commandsForResource(reference resourceReference, fallbackNamespace string) []string {
	if reference.kind == "" {
		return nil
	}
	namespace := reference.namespace
	if namespace == "" {
		namespace = fallbackNamespace
	}
	namespaced := func(resource string, output string) string {
		command := "kubectl get " + resource
		if reference.name != "" {
			command += " " + reference.name
		}
		if namespace != "" {
			command += " -n " + namespace
		}
		if output != "" {
			command += " " + output
		}
		return command
	}
	switch reference.kind {
	case "pod":
		if reference.name == "" {
			return []string{namespaced("pods", "-o wide")}
		}
		return []string{
			namespaced("pod", "-o wide"),
			"kubectl describe pod " + reference.name + " -n " + namespace,
		}
	case "service":
		if reference.name == "" {
			return []string{namespaced("services", "-o wide")}
		}
		return []string{
			namespaced("service", "-o wide"),
			"kubectl describe service " + reference.name + " -n " + namespace,
			"kubectl get endpointslices -n " + namespace + " -l kubernetes.io/service-name=" + reference.name + " -o wide",
		}
	case "deployment", "daemonset", "statefulset":
		resource := reference.kind
		commands := []string{namespaced(resource, "-o wide")}
		if reference.name != "" {
			commands = append(commands,
				"kubectl describe "+resource+" "+reference.name+" -n "+namespace,
				"kubectl rollout status "+resource+"/"+reference.name+" -n "+namespace,
			)
		}
		return commands
	case "persistentvolumeclaim":
		return []string{
			namespaced("pvc", "-o wide"),
			"kubectl describe pvc " + reference.name + " -n " + namespace,
		}
	case "namespace":
		name := reference.name
		if name == "" {
			name = namespace
		}
		return []string{"kubectl get namespace " + name, "kubectl describe namespace " + name}
	case "node":
		return []string{"kubectl get node " + reference.name + " -o wide", "kubectl describe node " + reference.name}
	case "customresourcedefinition":
		return []string{"kubectl get crd " + reference.name + " -o yaml"}
	case "ipaddresspool":
		return []string{namespaced("ipaddresspool.metallb.io", "-o yaml")}
	case "bgppeer":
		return []string{namespaced("bgppeer.metallb.io", "-o yaml")}
	case "bgpadvertisement":
		return []string{namespaced("bgpadvertisement.metallb.io", "-o yaml")}
	case "l2advertisement":
		return []string{namespaced("l2advertisement.metallb.io", "-o yaml")}
	}
	if strings.Contains(reference.kind, ".") {
		return []string{namespaced(reference.kind, "-o wide")}
	}
	return nil
}

func commandsForCheck(target string, check string, namespace string, finding Finding) []string {
	pod := podNameFromResource(finding.Resource)
	switch target {
	case "metallb":
		switch check {
		case "controller":
			return []string{"kubectl get deployment -n " + namespace + " -o wide", "kubectl get pods -n " + namespace + " -o wide"}
		case "speaker":
			return []string{"kubectl get daemonset -n " + namespace + " -o wide", "kubectl get pods -n " + namespace + " -o wide"}
		case "pods":
			return []string{"kubectl get pods -n " + namespace + " -o wide"}
		case "configuration", "address-pools":
			return []string{"kubectl get ipaddresspools.metallb.io -n " + namespace + " -o wide"}
		case "crds":
			return []string{"kubectl get crd | grep metallb.io"}
		case "bgp-configuration":
			return []string{"kubectl get bgppeers.metallb.io,bgpadvertisements.metallb.io -n " + namespace + " -o wide"}
		case "l2-configuration":
			return []string{"kubectl get l2advertisements.metallb.io -n " + namespace + " -o yaml"}
		case "bgp-sessions":
			if pod != "" {
				return []string{"kubectl exec -n " + namespace + " " + pod + " -c frr -- vtysh -c 'show bgp summary'"}
			}
		case "bgp-neighbors":
			parts := strings.Split(finding.Resource, "/")
			if len(parts) == 2 {
				return []string{"kubectl exec -n " + namespace + " " + parts[0] + " -c frr -- vtysh -c 'show bgp neighbors " + parts[1] + "'"}
			}
		case "bgp-routes":
			if pod != "" {
				return []string{"kubectl exec -n " + namespace + " " + pod + " -c frr -- vtysh -c 'show bgp ipv4 unicast'"}
			}
		case "advertised-routes":
			parts := strings.Split(finding.Resource, "/")
			if len(parts) == 2 {
				return []string{"kubectl exec -n " + namespace + " " + parts[0] + " -c frr -- vtysh -c 'show bgp neighbors " + parts[1] + " advertised-routes'"}
			}
		case "loadbalancer-services":
			return []string{"kubectl get services -A -o wide | grep LoadBalancer"}
		case "webhook":
			return []string{"kubectl get service,endpointslice -n " + namespace + " -o wide | grep webhook"}
		case "events":
			return warningEventsCommand(namespace)
		}
	case "prometheus":
		switch check {
		case "workloads":
			return []string{"kubectl get statefulset,deployment -n " + namespace + " -o wide | grep prometheus"}
		case "pods":
			return []string{"kubectl get pods -n " + namespace + " -o wide | grep prometheus"}
		case "services":
			return []string{"kubectl get service,endpointslice -n " + namespace + " -o wide | grep prometheus"}
		case "storage":
			return []string{"kubectl get pvc -n " + namespace + " -o wide"}
		case "operator-resources":
			return []string{"kubectl get prometheuses.monitoring.coreos.com,servicemonitors.monitoring.coreos.com,podmonitors.monitoring.coreos.com,prometheusrules.monitoring.coreos.com -A"}
		case "events":
			return warningEventsCommand(namespace)
		case "prometheus-api":
			return []string{"kubectl port-forward -n " + namespace + " service/prometheus-operated 9090:9090", "curl -s http://127.0.0.1:9090/-/ready"}
		case "scrape-targets":
			return []string{"kubectl port-forward -n " + namespace + " service/prometheus-operated 9090:9090", "curl -s 'http://127.0.0.1:9090/api/v1/targets?state=active'"}
		case "rules":
			return []string{"kubectl port-forward -n " + namespace + " service/prometheus-operated 9090:9090", "curl -s http://127.0.0.1:9090/api/v1/rules"}
		}
	case "amtool":
		return amtoolCommands(check, namespace, pod)
	case "podinfo":
		return podInfoCommands(check, namespace, pod, finding)
	case "netcap":
		return netcapCommands(namespace, finding)
	}
	if check == "events" {
		return warningEventsCommand(namespace)
	}
	return nil
}

func amtoolCommands(check string, namespace string, pod string) []string {
	if check == "statefulset" {
		return []string{"kubectl get statefulset -n " + namespace + " -o wide | grep alertmanager"}
	}
	if check == "pods" || check == "replica-consistency" {
		return []string{"kubectl get pods -n " + namespace + " -o wide | grep alertmanager"}
	}
	if pod == "" {
		return nil
	}
	prefix := "kubectl exec -n " + namespace + " " + pod + " -c alertmanager -- amtool --alertmanager.url=http://localhost:9093"
	switch check {
	case "pod-exec", "amtool-version":
		return []string{prefix + " --version"}
	case "alerts":
		return []string{prefix + " alert query"}
	case "alerts-extended":
		return []string{prefix + " -o extended alert query"}
	case "configuration":
		return []string{prefix + " config show"}
	case "routes":
		return []string{prefix + " config routes show"}
	case "silences":
		return []string{prefix + " silence query"}
	case "cluster":
		return []string{prefix + " cluster show"}
	}
	return nil
}

func podInfoCommands(check string, namespace string, pod string, finding Finding) []string {
	if pod == "" {
		if check == "pods" {
			return []string{"kubectl get pods -n " + namespace + " -o wide"}
		}
		return nil
	}
	commands := []string{
		"kubectl get pod " + pod + " -n " + namespace + " -o wide",
		"kubectl get pod " + pod + " -n " + namespace + " -o jsonpath='{.spec.nodeName}{\"\\n\"}{.status.podIP}{\"\\n\"}{.status.containerStatuses[*].containerID}{\"\\n\"}'",
	}
	if check == "containers" {
		commands = append(commands, "kubectl get pod "+pod+" -n "+namespace+" -o jsonpath='{.spec.initContainers[*].name}{\"\\n\"}{.spec.containers[*].name}{\"\\n\"}{.spec.ephemeralContainers[*].name}{\"\\n\"}'")
	}
	if check == "runtime" || check == "inspect" || check == "network-namespace" || check == "ssh" {
		nodeIP := detailValue(finding.Detail, "Node IP")
		if nodeIP == "" {
			nodeIP = "<node-ip>"
		}
		containerID := detailValue(finding.Detail, "CRI container ID")
		pid := detailValue(finding.Detail, "Network PID")
		commands = append(commands, "ssh <user>@"+nodeIP+" 'crictl ps -a'")
		if containerID != "" {
			commands = append(commands, "ssh <user>@"+nodeIP+" 'crictl inspect "+containerID+"'")
		}
		if pid != "" {
			commands = append(commands, "ssh <user>@"+nodeIP+" 'nsenter -t "+pid+" -n'")
		}
	}
	return commands
}

func netcapCommands(namespace string, finding Finding) []string {
	pod := podNameFromResource(finding.Resource)
	if pod == "" {
		return nil
	}
	commands := []string{
		"kubectl get pod " + pod + " -n " + namespace + " -o wide",
		"kubectl get pod " + pod + " -n " + namespace + " -o jsonpath='{.spec.nodeName}{\"\\n\"}{.status.containerStatuses[*].containerID}{\"\\n\"}'",
	}
	if remoteCommand := detailValue(finding.Detail, "Remote command"); remoteCommand != "" {
		nodeIP := detailValue(finding.Detail, "Node IP")
		if nodeIP == "" {
			nodeIP = "<node-ip>"
		}
		commands = append(commands, "ssh <user>@"+nodeIP+" -- sh -c "+shellQuote(remoteCommand))
	}
	return commands
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func warningEventsCommand(namespace string) []string {
	return []string{"kubectl get events -n " + namespace + " --field-selector type=Warning --sort-by=.lastTimestamp"}
}

func parseResource(resource string) resourceReference {
	if resource == "" || strings.Contains(resource, "://") {
		return resourceReference{}
	}
	parts := strings.Split(resource, "/")
	switch {
	case len(parts) >= 3:
		if isKnownResourceKind(parts[0]) {
			return resourceReference{kind: parts[0], namespace: parts[1], name: parts[2]}
		}
	case len(parts) == 2:
		if isKnownResourceKind(parts[0]) {
			return resourceReference{kind: parts[0], name: parts[1]}
		}
	case len(parts) == 1:
		if strings.Contains(parts[0], ".") && !strings.Contains(parts[0], " ") {
			return resourceReference{kind: parts[0]}
		}
	}
	return resourceReference{}
}

func isKnownResourceKind(kind string) bool {
	switch kind {
	case "pod", "service", "deployment", "daemonset", "statefulset", "persistentvolumeclaim", "namespace", "node", "customresourcedefinition", "ipaddresspool", "bgppeer", "bgpadvertisement", "l2advertisement":
		return true
	default:
		return false
	}
}

func podNameFromResource(resource string) string {
	reference := parseResource(resource)
	if reference.kind == "pod" {
		return reference.name
	}
	return ""
}

func detailValue(detail string, key string) string {
	prefix := key + ":"
	for _, line := range strings.Split(detail, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func baseCheck(check string) string {
	parts := strings.Split(check, "/")
	return parts[len(parts)-1]
}

func uniqueCommands(commands []string) []string {
	seen := make(map[string]struct{}, len(commands))
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		if _, exists := seen[command]; exists {
			continue
		}
		seen[command] = struct{}{}
		result = append(result, command)
	}
	return result
}
