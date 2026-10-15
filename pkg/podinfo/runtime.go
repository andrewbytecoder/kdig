package podinfo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type runtimeContainerList struct {
	Containers []runtimeContainer `json:"containers"`
}

type runtimeContainer struct {
	ID           string            `json:"id"`
	PodSandboxID string            `json:"podSandboxId"`
	Metadata     runtimeMetadata   `json:"metadata"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
}

type runtimeMetadata struct {
	Name    string `json:"name"`
	Attempt uint32 `json:"attempt"`
}

type containerInspection struct {
	Info struct {
		PID         int `json:"pid"`
		RuntimeSpec struct {
			Linux struct {
				Namespaces []runtimeNamespace `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

type runtimeNamespace struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

func selectPodContainers(output string, pod corev1.Pod) ([]runtimeContainer, error) {
	var list runtimeContainerList
	if err := json.Unmarshal([]byte(output), &list); err != nil {
		return nil, fmt.Errorf("decode crictl ps JSON: %w", err)
	}
	expectedNames := make(map[string]struct{})
	for _, container := range podContainers(pod) {
		expectedNames[container.name] = struct{}{}
	}
	selected := make(map[string]runtimeContainer)
	for _, container := range list.Containers {
		if container.Labels["io.kubernetes.pod.name"] != pod.Name ||
			container.Labels["io.kubernetes.pod.namespace"] != pod.Namespace {
			continue
		}
		uid := container.Labels["io.kubernetes.pod.uid"]
		if uid != "" && pod.UID != "" && uid != string(pod.UID) {
			continue
		}
		name := container.Metadata.Name
		if labelName := container.Labels["io.kubernetes.container.name"]; labelName != "" {
			name = labelName
			container.Metadata.Name = labelName
		}
		if _, expected := expectedNames[name]; !expected {
			continue
		}
		current, exists := selected[name]
		if !exists || container.Metadata.Attempt > current.Metadata.Attempt ||
			(container.Metadata.Attempt == current.Metadata.Attempt && isRunning(container.State) && !isRunning(current.State)) {
			selected[name] = container
		}
	}
	result := make([]runtimeContainer, 0, len(selected))
	for _, container := range selected {
		result = append(result, container)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Metadata.Name < result[right].Metadata.Name
	})
	return result, nil
}

func parseInspection(output string) (containerInspection, error) {
	var inspection containerInspection
	if err := json.Unmarshal([]byte(output), &inspection); err != nil {
		return inspection, fmt.Errorf("decode crictl inspect JSON: %w", err)
	}
	return inspection, nil
}

func (inspection containerInspection) networkPID() int {
	for _, namespace := range inspection.Info.RuntimeSpec.Linux.Namespaces {
		if !strings.EqualFold(namespace.Type, "network") || namespace.Path == "" {
			continue
		}
		parts := strings.Split(strings.Trim(namespace.Path, "/"), "/")
		if len(parts) != 4 || parts[0] != "proc" || parts[2] != "ns" || parts[3] != "net" {
			continue
		}
		pid, err := strconv.Atoi(parts[1])
		if err == nil {
			return pid
		}
	}
	return inspection.Info.PID
}

func isRunning(state string) bool {
	return strings.EqualFold(state, "CONTAINER_RUNNING") || strings.EqualFold(state, "running")
}
