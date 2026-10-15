package diagnostic

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

func Write(writer io.Writer, report Report, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "table":
		return writeTable(writer, report)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeTable(writer io.Writer, report Report) error {
	summary := report.Summary()
	metadata := tablewriter.NewWriter(writer)
	metadata.Header([]string{"Target", "Namespace", "Duration"})
	metadata.Append([]string{report.Target, report.Namespace, report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond).String()})
	if err := metadata.Render(); err != nil {
		return err
	}

	table := tablewriter.NewTable(writer, tablewriter.WithConfig(tablewriter.Config{
		Row: tw.CellConfig{
			Alignment: tw.CellAlignment{Global: tw.AlignLeft},
			ColMaxWidths: tw.CellWidth{PerColumn: tw.Mapper[int, int]{
				0: 10,
				1: 24,
				2: 36,
				3: 45,
				4: 60,
			}},
		},
	}))
	table.Header([]string{"Severity", "Check", "Resource", "Summary", "Details"})
	for _, finding := range report.Findings {
		details := finding.Detail
		if finding.Suggestion != "" {
			if details != "" {
				details += "\n"
			}
			details += "Suggestion: " + finding.Suggestion
		}
		table.Append([]string{
			strings.ToUpper(string(finding.Severity)),
			finding.Check,
			finding.Resource,
			finding.Summary,
			details,
		})
	}
	if err := table.Render(); err != nil {
		return err
	}

	summaryTable := tablewriter.NewWriter(writer)
	summaryTable.Header([]string{"Critical", "Warning", "Info", "Total"})
	summaryTable.Append([]string{
		fmt.Sprint(summary.Critical),
		fmt.Sprint(summary.Warning),
		fmt.Sprint(summary.Info),
		fmt.Sprint(len(report.Findings)),
	})
	return summaryTable.Render()
}
