package podinfo

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCheckerInspectsAllPodContainers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-0",
			Namespace: "apps",
			UID:       types.UID("pod-uid"),
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
			Containers: []corev1.Container{
				{Name: "api"},
				{Name: "sidecar"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.1.10",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "api", ContainerID: "containerd://container-api", Ready: true},
				{Name: "sidecar", ContainerID: "containerd://container-sidecar", Ready: true},
			},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type:    corev1.NodeInternalIP,
			Address: "192.0.2.10",
		}}},
	}
	objects := []runtime.Object{pod, node}
	runner := &fakeRunner{}
	checker := NewChecker(&kube.Clients{Kubernetes: fake.NewSimpleClientset(objects...)}, Options{
		Namespace: "apps",
		Pod:       "api-0",
		Username:  "root",
		SSHPort:   22,
	}, runner)

	report := checker.Run(context.Background())

	if report.Target != "podinfo" || report.Namespace != "apps" {
		t.Fatalf("unexpected report identity: %#v", report)
	}
	if got := runner.callCount(); got != 6 {
		t.Fatalf("remote command count = %d, want 6", got)
	}
	if findingCount(report.Findings, "network-namespace", diagnostic.SeverityInfo) != 2 {
		t.Fatalf("expected network namespace details for two containers: %#v", report.Findings)
	}
	for _, expected := range []string{"api", "sidecar", "Network PID: 4242", "nsenter -t 4242 -n", "net:[4026533000]"} {
		if !findingsContain(report.Findings, expected) {
			t.Fatalf("findings do not contain %q: %#v", expected, report.Findings)
		}
	}
}

func TestCheckerTraversesAllPodsWhenPodNameIsEmpty(t *testing.T) {
	firstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "apps", UID: types.UID("pod-uid")},
		Spec: corev1.PodSpec{
			NodeName:   "worker-1",
			Containers: []corev1.Container{{Name: "api"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.10"},
	}
	secondPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-0", Namespace: "apps", UID: types.UID("worker-uid")},
		Spec: corev1.PodSpec{
			NodeName:   "worker-1",
			Containers: []corev1.Container{{Name: "worker"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.11"},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{
			Type:    corev1.NodeInternalIP,
			Address: "192.0.2.10",
		}}},
	}
	runner := &fakeRunner{}
	checker := NewChecker(&kube.Clients{
		Kubernetes: fake.NewSimpleClientset(firstPod, secondPod, node),
	}, Options{Namespace: "apps", Username: "root", SSHPort: 22}, runner)

	report := checker.Run(context.Background())

	for _, expected := range []string{"Inspecting 2 Pods", "pod/apps/api-0", "pod/apps/worker-0"} {
		if !findingsContain(report.Findings, expected) {
			t.Fatalf("namespace traversal findings do not contain %q: %#v", expected, report.Findings)
		}
	}
	if got := runner.callCount(); got != 8 {
		t.Fatalf("remote command count = %d, want 8", got)
	}
}

func TestSelectPodContainersUsesLatestAttempt(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "apps", UID: types.UID("pod-uid")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
	}
	output := `{"containers":[
  {"id":"old","metadata":{"name":"api","attempt":0},"state":"CONTAINER_EXITED","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"pod-uid"}},
  {"id":"current","metadata":{"name":"api","attempt":1},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"pod-uid"}},
  {"id":"other","metadata":{"name":"api","attempt":2},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"other-uid"}}
]}`

	containers, err := selectPodContainers(output, pod)
	if err != nil {
		t.Fatalf("selectPodContainers() error = %v", err)
	}
	if len(containers) != 1 || containers[0].ID != "current" {
		t.Fatalf("selectPodContainers() = %#v, want current attempt", containers)
	}
}

func TestInspectionPrefersNetworkNamespacePID(t *testing.T) {
	inspection, err := parseInspection(`{"info":{"pid":1234,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/proc/4321/ns/net"}]}}}}`)
	if err != nil {
		t.Fatalf("parseInspection() error = %v", err)
	}
	if got := inspection.networkPID(); got != 4321 {
		t.Fatalf("networkPID() = %d, want 4321", got)
	}
}

type fakeRunner struct {
	mutex sync.Mutex
	calls []string
}

func (runner *fakeRunner) Run(_ context.Context, address string, command string) (string, error) {
	runner.mutex.Lock()
	runner.calls = append(runner.calls, address+" "+command)
	runner.mutex.Unlock()
	switch {
	case command == "crictl --version":
		return "crictl version v1.34.0", nil
	case command == "crictl ps -a -o json":
		return `{"containers":[
  {"id":"container-api","metadata":{"name":"api","attempt":0},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"pod-uid","io.kubernetes.container.name":"api"}},
  {"id":"container-sidecar","metadata":{"name":"sidecar","attempt":0},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"api-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"pod-uid","io.kubernetes.container.name":"sidecar"}},
  {"id":"container-worker","metadata":{"name":"worker","attempt":0},"state":"CONTAINER_RUNNING","labels":{"io.kubernetes.pod.name":"worker-0","io.kubernetes.pod.namespace":"apps","io.kubernetes.pod.uid":"worker-uid","io.kubernetes.container.name":"worker"}}
]}`, nil
	case strings.HasPrefix(command, "crictl inspect "):
		return `{"info":{"pid":2000,"runtimeSpec":{"linux":{"namespaces":[{"type":"network","path":"/proc/4242/ns/net"}]}}}}`, nil
	case command == "readlink /proc/4242/ns/net":
		return "net:[4026533000]\n", nil
	default:
		return "", nil
	}
}

func (runner *fakeRunner) callCount() int {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return len(runner.calls)
}

func findingCount(findings []diagnostic.Finding, check string, severity diagnostic.Severity) int {
	count := 0
	for _, finding := range findings {
		if finding.Check == check && finding.Severity == severity {
			count++
		}
	}
	return count
}

func findingsContain(findings []diagnostic.Finding, expected string) bool {
	for _, finding := range findings {
		if strings.Contains(finding.Resource, expected) || strings.Contains(finding.Summary, expected) || strings.Contains(finding.Detail, expected) {
			return true
		}
	}
	return false
}
