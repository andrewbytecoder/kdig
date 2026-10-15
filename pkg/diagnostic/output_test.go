package diagnostic

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteText(t *testing.T) {
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

	if err := Write(&output, report, "text"); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, expected := range []string{"Target: metallb", "[WARNING] bgp-neighbors", "BGP neighbor state", "Suggestion:", "Summary:"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("text output does not contain %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "┌") || strings.Contains(output.String(), "|") {
		t.Fatalf("text output unexpectedly contains table borders:\n%s", output.String())
	}
}
