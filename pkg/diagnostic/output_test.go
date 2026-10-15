package diagnostic

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteTable(t *testing.T) {
	start := time.Date(2026, time.October, 15, 10, 0, 0, 0, time.UTC)
	report := Report{
		Target:     "metallb",
		Namespace:  "metallb-system",
		StartedAt:  start,
		FinishedAt: start.Add(time.Second),
		Findings: []Finding{{
			Severity:   SeverityWarning,
			Check:      "bgp-neighbors",
			Resource:   "speaker/10.0.0.1",
			Summary:    "BGP neighbor state: Active",
			Detail:     "Node: worker-a",
			Suggestion: "Check TCP/179 connectivity.",
		}},
	}
	var output bytes.Buffer

	if err := Write(&output, report, "table"); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, expected := range []string{"TARGET", "SEVERITY", "BGP neighbor state", "Suggestion:", "CRITICAL"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("table output does not contain %q:\n%s", expected, output.String())
		}
	}
}
