package diagnostic

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

func Write(writer io.Writer, report Report, format string) error {
	report.enrichFindings()
	switch format {
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "text":
		return writeText(writer, report)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeText(writer io.Writer, report Report) error {
	var output strings.Builder
	duration := report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond)
	fmt.Fprintf(&output, "Target: %s\n", report.Target)
	fmt.Fprintf(&output, "Namespace: %s\n", report.Namespace)
	fmt.Fprintf(&output, "Duration: %s\n\n", duration)

	for _, finding := range report.Findings {
		fmt.Fprintf(&output, "[%s] %s\n", strings.ToUpper(string(finding.Severity)), finding.Check)
		if finding.Resource != "" {
			fmt.Fprintf(&output, "  Resource: %s\n", finding.Resource)
		}
		fmt.Fprintf(&output, "  %s\n", finding.Summary)
		writeIndented(&output, "Describe", finding.Describe)
		writeIndented(&output, "Detail", finding.Detail)
		writeIndented(&output, "Suggestion", finding.Suggestion)
		writeIndented(&output, "Verify", strings.Join(finding.Verify, "\n"))
		output.WriteByte('\n')
	}

	summary := report.Summary()
	fmt.Fprintf(
		&output,
		"Summary: %d critical, %d warning, %d info\n",
		summary.Critical,
		summary.Warning,
		summary.Info,
	)
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeIndented(output *strings.Builder, label string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	lines := strings.Split(value, "\n")
	fmt.Fprintf(output, "  %s: %s\n", label, lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintf(output, "    %s\n", line)
	}
}
