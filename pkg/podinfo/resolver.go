package podinfo

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkTarget struct {
	Namespace        string
	Pod              string
	Container        string
	ContainerID      string
	Node             string
	NodeIP           string
	SSHAddress       string
	NetworkPID       int
	NetworkNamespace string
}

func ResolveNetworkTarget(
	ctx context.Context,
	clients *kube.Clients,
	runner RemoteRunner,
	namespace string,
	podName string,
	containerName string,
	sshPort int,
) (NetworkTarget, error) {
	target := NetworkTarget{Namespace: namespace, Pod: podName}
	pod, err := clients.Kubernetes.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return target, fmt.Errorf("get pod %s/%s: %w", namespace, podName, err)
	}
	if pod.Spec.NodeName == "" {
		return target, fmt.Errorf("pod %s/%s is not assigned to a node", namespace, podName)
	}
	node, err := clients.Kubernetes.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return target, fmt.Errorf("get node %s: %w", pod.Spec.NodeName, err)
	}
	nodeIP := preferredNodeIP(*node)
	if nodeIP == "" {
		return target, fmt.Errorf("node %s has no InternalIP or ExternalIP", node.Name)
	}
	target.Node = node.Name
	target.NodeIP = nodeIP
	target.SSHAddress = net.JoinHostPort(nodeIP, strconv.Itoa(sshPort))

	containersOutput, err := runner.Run(ctx, target.SSHAddress, "crictl ps -a -o json")
	if err != nil {
		return target, fmt.Errorf("list CRI containers on node %s: %w", node.Name, err)
	}
	containers, err := selectPodContainers(containersOutput, *pod)
	if err != nil {
		return target, err
	}
	container, err := selectNetworkContainer(containers, containerName)
	if err != nil {
		return target, err
	}
	target.Container = container.Metadata.Name
	target.ContainerID = container.ID

	inspectionOutput, err := runner.Run(ctx, target.SSHAddress, "crictl inspect "+shellQuote(container.ID))
	if err != nil {
		return target, fmt.Errorf("inspect CRI container %s: %w", container.Metadata.Name, err)
	}
	inspection, err := parseInspection(inspectionOutput)
	if err != nil {
		return target, err
	}
	target.NetworkPID = inspection.networkPID()
	if target.NetworkPID <= 0 {
		return target, fmt.Errorf("container %s has no usable network namespace PID", container.Metadata.Name)
	}
	namespaceOutput, err := runner.Run(ctx, target.SSHAddress, fmt.Sprintf("readlink /proc/%d/ns/net", target.NetworkPID))
	if err != nil {
		return target, fmt.Errorf("read network namespace for PID %d: %w", target.NetworkPID, err)
	}
	target.NetworkNamespace = strings.TrimSpace(namespaceOutput)
	return target, nil
}

func selectNetworkContainer(containers []runtimeContainer, requested string) (runtimeContainer, error) {
	if len(containers) == 0 {
		return runtimeContainer{}, fmt.Errorf("no CRI containers matched the pod")
	}
	if requested == "" {
		for _, container := range containers {
			if isRunning(container.State) {
				return container, nil
			}
		}
		return containers[0], nil
	}
	for _, container := range containers {
		if container.Metadata.Name == requested {
			return container, nil
		}
	}
	return runtimeContainer{}, fmt.Errorf("container %q was not found in CRI output", requested)
}
