package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
)

func TestCheckPrometheusAPIFindsTargetAndRuleFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/-/ready":
			writer.WriteHeader(http.StatusOK)
		case "/api/v1/targets":
			_, _ = writer.Write([]byte(`{"status":"success","data":{"activeTargets":[{"health":"down","lastError":"connection refused","scrapeUrl":"http://api:8080/metrics","discoveredLabels":{"job":"api"}}]}}`))
		case "/api/v1/rules":
			_, _ = writer.Write([]byte(`{"status":"success","data":{"groups":[{"name":"alerts","rules":[{"name":"BadRule","health":"err","lastError":"parse error"}]}]}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	checker := &Checker{
		options:    Options{PrometheusURL: server.URL},
		httpClient: &http.Client{Timeout: time.Second},
	}
	report := diagnostic.Report{}
	checker.checkPrometheusAPI(context.Background(), &report)

	if countFindings(report.Findings, "scrape-targets", diagnostic.SeverityWarning) != 1 {
		t.Fatalf("expected one unhealthy scrape target, got %#v", report.Findings)
	}
	if countFindings(report.Findings, "rules", diagnostic.SeverityWarning) != 1 {
		t.Fatalf("expected one unhealthy rule, got %#v", report.Findings)
	}
}

func countFindings(findings []diagnostic.Finding, check string, severity diagnostic.Severity) int {
	count := 0
	for _, finding := range findings {
		if finding.Check == check && finding.Severity == severity {
			count++
		}
	}
	return count
}
