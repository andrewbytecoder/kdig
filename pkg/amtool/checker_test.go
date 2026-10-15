package amtool

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	"github.com/andrewbytecoder/kdig/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCheckerTraversesAlertmanagerStatefulSetPods(t *testing.T) {
	replicas := int32(3)
	objects := []runtime.Object{
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main", Namespace: "monitoring", UID: "alertmanager-main-uid"},
			Spec: appsv1.StatefulSetSpec{
				Replicas:    &replicas,
				Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "alertmanager"}},
				ServiceName: "alertmanager-operated",
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name:  "alertmanager",
						Image: "alertmanager:test",
						Ports: []corev1.ContainerPort{{ContainerPort: 9093}},
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(9093)},
						}},
					}}},
				},
			},
			Status: appsv1.StatefulSetStatus{ReadyReplicas: 3},
		},
	}
	for ordinal := 0; ordinal < 3; ordinal++ {
		objects = append(objects, alertmanagerPod(ordinal))
	}
	executor := &fakeExecutor{}
	checker := NewChecker(&kube.Clients{
		Kubernetes: fake.NewSimpleClientset(objects...),
		PodExec:    executor,
	}, Options{})

	report := checker.Run(context.Background())

	if report.Namespace != "monitoring" || report.Target != "amtool" {
		t.Fatalf("unexpected report identity: %#v", report)
	}
	if got := executor.callCount(); got != 21 {
		t.Fatalf("pod exec calls = %d, want 21", got)
	}
	for ordinal := 0; ordinal < 3; ordinal++ {
		pod := "alertmanager-main-" + strconv.Itoa(ordinal)
		if !executor.calledPod(pod) {
			t.Fatalf("expected commands to run in %s", pod)
		}
	}
	if findingCount(report.Findings, "alerts", diagnostic.SeverityWarning) != 3 {
		t.Fatalf("expected one actionable alert finding per pod: %#v", report.Findings)
	}
	if findingCount(report.Findings, "replica-consistency", diagnostic.SeverityInfo) != 1 {
		t.Fatalf("expected consistent configuration finding: %#v", report.Findings)
	}
}

func TestCheckerReportsMissingStatefulSet(t *testing.T) {
	checker := NewChecker(&kube.Clients{Kubernetes: fake.NewSimpleClientset()}, Options{})
	report := checker.Run(context.Background())

	if findingCount(report.Findings, "statefulset", diagnostic.SeverityCritical) != 1 {
		t.Fatalf("expected missing StatefulSet finding: %#v", report.Findings)
	}
}

func TestRedactConfig(t *testing.T) {
	input := "global:\n  slack_api_url: https://hooks.example/secret\n  smtp_auth_password: password\nreceivers:\n- name: team\n  webhook_configs:\n  - url: https://example/token"
	output := redactConfig(input)
	for _, secret := range []string{"hooks.example", ": password", "example/token"} {
		if strings.Contains(output, secret) {
			t.Fatalf("redactConfig() leaked %q:\n%s", secret, output)
		}
	}
	if !strings.Contains(output, "- name: team") {
		t.Fatalf("redactConfig() removed non-sensitive configuration:\n%s", output)
	}
}

func TestAlertDigestIgnoresAlertOrder(t *testing.T) {
	first := []alert{
		{Labels: map[string]string{"alertname": "A"}},
		{Labels: map[string]string{"alertname": "B"}},
	}
	second := []alert{first[1], first[0]}
	if alertDigest(first) != alertDigest(second) {
		t.Fatal("alertDigest() must not depend on API result order")
	}
}

func alertmanagerPod(ordinal int) *corev1.Pod {
	ready := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alertmanager-main-" + strconv.Itoa(ordinal),
			Namespace: "monitoring",
			Labels:    map[string]string{"app": "alertmanager"},
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "StatefulSet",
				Name: "alertmanager-main",
			}},
		},
		Spec: corev1.PodSpec{
			NodeName:   "worker-" + strconv.Itoa(ordinal),
			Containers: []corev1.Container{{Name: "alertmanager"}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0." + strconv.Itoa(ordinal+1),
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "alertmanager", Ready: ready}},
		},
	}
}

type fakeExecutor struct {
	mutex sync.Mutex
	calls []string
}

func (executor *fakeExecutor) Exec(_ context.Context, namespace, pod, container string, command []string) (string, string, error) {
	executor.mutex.Lock()
	executor.calls = append(executor.calls, namespace+"/"+pod+"/"+container+" "+strings.Join(command, " "))
	executor.mutex.Unlock()
	joined := strings.Join(command, " ")
	switch {
	case strings.Contains(joined, "--version"):
		return "amtool, version 0.28.0", "", nil
	case strings.Contains(joined, "-o json alert query"):
		return `[
  {"labels":{"alertname":"Watchdog","severity":"none"},"status":{"state":"active"}},
  {"labels":{"alertname":"KubePodCrashLooping","severity":"warning"},"status":{"state":"active"}}
]`, "", nil
	case strings.Contains(joined, "-o extended alert query"):
		return "Labels Annotations Starts At Ends At Generator URL State\nalertname=Watchdog active", "", nil
	case strings.Contains(joined, "config show"):
		return "route:\n  receiver: Default\nreceivers:\n- name: Default", "", nil
	case strings.Contains(joined, "config routes show"):
		return "Routing tree:\n.\n└── default-route receiver: Default", "", nil
	case strings.Contains(joined, "-o json silence query"):
		return `[{"id":"silence-1","status":{"state":"active"}}]`, "", nil
	case strings.Contains(joined, "cluster show"):
		return "Peer State\nalertmanager-main-0 ready", "", nil
	default:
		return "", "", nil
	}
}

func (executor *fakeExecutor) callCount() int {
	executor.mutex.Lock()
	defer executor.mutex.Unlock()
	return len(executor.calls)
}

func (executor *fakeExecutor) calledPod(pod string) bool {
	executor.mutex.Lock()
	defer executor.mutex.Unlock()
	for _, call := range executor.calls {
		if strings.Contains(call, "/"+pod+"/") {
			return true
		}
	}
	return false
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
