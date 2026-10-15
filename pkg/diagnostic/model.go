package diagnostic

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Severity   Severity `json:"severity"`
	Check      string   `json:"check"`
	Resource   string   `json:"resource,omitempty"`
	Summary    string   `json:"summary"`
	Detail     string   `json:"detail,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
}

type Report struct {
	Target     string    `json:"target"`
	Namespace  string    `json:"namespace"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Findings   []Finding `json:"findings"`
}

type Summary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

func (report *Report) Add(finding Finding) {
	report.Findings = append(report.Findings, finding)
}

func (report *Report) Complete() {
	report.FinishedAt = time.Now()
	sort.SliceStable(report.Findings, func(left, right int) bool {
		leftRank := severityRank(report.Findings[left].Severity)
		rightRank := severityRank(report.Findings[right].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if report.Findings[left].Check != report.Findings[right].Check {
			return report.Findings[left].Check < report.Findings[right].Check
		}
		return report.Findings[left].Resource < report.Findings[right].Resource
	})
}

func (report Report) Summary() Summary {
	var summary Summary
	for _, finding := range report.Findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityWarning:
			summary.Warning++
		default:
			summary.Info++
		}
	}
	return summary
}

func (report Report) ExitCode() int {
	summary := report.Summary()
	if summary.Critical > 0 {
		return 2
	}
	if summary.Warning > 0 {
		return 1
	}
	return 0
}

func Merge(target, namespace string, reports ...Report) Report {
	merged := Report{
		Target:    target,
		Namespace: namespace,
		StartedAt: time.Now(),
	}
	for _, report := range reports {
		if report.StartedAt.Before(merged.StartedAt) {
			merged.StartedAt = report.StartedAt
		}
		for _, finding := range report.Findings {
			finding.Check = report.Target + "/" + finding.Check
			merged.Findings = append(merged.Findings, finding)
		}
	}
	merged.Complete()
	return merged
}

type StatusError struct {
	Code int
}

func (err *StatusError) Error() string {
	return fmt.Sprintf("diagnosis completed with exit code %d", err.Code)
}

func Resource(kind, namespace, name string) string {
	parts := []string{strings.ToLower(kind)}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}
