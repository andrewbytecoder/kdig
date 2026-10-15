package diagnostic

import "testing"

func TestReportExitCode(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{name: "healthy", findings: []Finding{{Severity: SeverityInfo}}, want: 0},
		{name: "warning", findings: []Finding{{Severity: SeverityWarning}}, want: 1},
		{name: "critical", findings: []Finding{{Severity: SeverityWarning}, {Severity: SeverityCritical}}, want: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := Report{Findings: test.findings}
			if got := report.ExitCode(); got != test.want {
				t.Fatalf("ExitCode() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestResource(t *testing.T) {
	if got, want := Resource("Service", "default", "api"), "service/default/api"; got != want {
		t.Fatalf("Resource() = %q, want %q", got, want)
	}
}
