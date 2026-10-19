package diagnostic

import (
	"strings"
	"testing"
)

func TestEnrichFindingForPodNetworkNamespace(t *testing.T) {
	finding := enrichFinding("podinfo", "apps", Finding{
		Check:    "network-namespace",
		Resource: "pod/apps/api-0/api",
		Detail:   "Node IP: 192.0.2.10\nCRI container ID: abc123\nNetwork PID: 4242",
	})

	if finding.Describe == "" {
		t.Fatal("Describe is empty")
	}
	for _, expected := range []string{
		"kubectl get pod api-0 -n apps -o wide",
		"ssh <user>@192.0.2.10 'crictl inspect abc123'",
		"ssh <user>@192.0.2.10 'nsenter -t 4242 -n'",
	} {
		if !containsCommand(finding.Verify, expected) {
			t.Fatalf("Verify does not contain %q: %#v", expected, finding.Verify)
		}
	}
}

func TestEnrichFindingForAmtool(t *testing.T) {
	finding := enrichFinding("amtool", "monitoring", Finding{
		Check:    "alerts-extended",
		Resource: "pod/monitoring/alertmanager-main-0",
	})

	want := "kubectl exec -n monitoring alertmanager-main-0 -c alertmanager -- amtool --alertmanager.url=http://localhost:9093 -o extended alert query"
	if !containsCommand(finding.Verify, want) {
		t.Fatalf("Verify does not contain amtool command: %#v", finding.Verify)
	}
}

func TestCustomGuidanceIsPreserved(t *testing.T) {
	finding := enrichFinding("prometheus", "monitoring", Finding{
		Check:    "rules",
		Describe: "Custom description",
		Verify:   []string{"custom command"},
	})
	if finding.Describe != "Custom description" || len(finding.Verify) != 1 || finding.Verify[0] != "custom command" {
		t.Fatalf("custom guidance was changed: %#v", finding)
	}
}

func containsCommand(commands []string, expected string) bool {
	for _, command := range commands {
		if strings.Contains(command, expected) {
			return true
		}
	}
	return false
}
