package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
)

func (checker *Checker) checkPrometheusAPI(ctx context.Context, report *diagnostic.Report) {
	baseURL := strings.TrimRight(checker.options.PrometheusURL, "/")
	parsedURL, err := url.ParseRequestURI(baseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		detail := "URL must include a scheme and host"
		if err != nil {
			detail = err.Error()
		}
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityCritical, Check: "prometheus-api", Summary: "Invalid Prometheus URL", Detail: detail, Verify: []string{"curl -v " + shellQuote(baseURL)}})
		return
	}
	if err := checker.checkReady(ctx, baseURL); err != nil {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "prometheus-api",
			Resource:   baseURL,
			Summary:    "Prometheus readiness check failed",
			Detail:     err.Error(),
			Suggestion: "Verify the URL, network path, Prometheus logs, configuration, and storage health.",
			Verify:     []string{"curl -v " + shellQuote(baseURL+"/-/ready")},
		})
		return
	}
	report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "prometheus-api", Resource: baseURL, Summary: "Prometheus is ready", Verify: []string{"curl -v " + shellQuote(baseURL+"/-/ready")}})
	checker.checkTargets(ctx, report, baseURL)
	checker.checkRules(ctx, report, baseURL)
}

func (checker *Checker) checkReady(ctx context.Context, baseURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/-/ready", nil)
	if err != nil {
		return err
	}
	response, err := checker.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (checker *Checker) checkTargets(ctx context.Context, report *diagnostic.Report, baseURL string) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			ActiveTargets []struct {
				Health           string            `json:"health"`
				LastError        string            `json:"lastError"`
				ScrapeURL        string            `json:"scrapeUrl"`
				DiscoveredLabels map[string]string `json:"discoveredLabels"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := checker.getJSON(ctx, baseURL+"/api/v1/targets?state=active", &response); err != nil {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityWarning, Check: "scrape-targets", Summary: "Cannot query Prometheus scrape targets", Detail: err.Error(), Verify: []string{"curl -s " + shellQuote(baseURL+"/api/v1/targets?state=active")}})
		return
	}
	unhealthy := 0
	for _, target := range response.Data.ActiveTargets {
		if target.Health == "up" {
			continue
		}
		unhealthy++
		job := target.DiscoveredLabels["job"]
		resource := target.ScrapeURL
		if job != "" {
			resource = job + " " + target.ScrapeURL
		}
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "scrape-targets",
			Resource:   resource,
			Summary:    fmt.Sprintf("Scrape target is %s", target.Health),
			Detail:     target.LastError,
			Suggestion: "Verify service discovery labels, endpoint reachability, TLS credentials, and the metrics path.",
			Verify:     []string{"curl -s " + shellQuote(baseURL+"/api/v1/targets?state=active")},
		})
	}
	if unhealthy == 0 {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "scrape-targets", Summary: fmt.Sprintf("All %d active scrape targets are healthy", len(response.Data.ActiveTargets)), Verify: []string{"curl -s " + shellQuote(baseURL+"/api/v1/targets?state=active")}})
	}
}

func (checker *Checker) checkRules(ctx context.Context, report *diagnostic.Report, baseURL string) {
	var response struct {
		Data struct {
			Groups []struct {
				Name  string `json:"name"`
				Rules []struct {
					Name      string `json:"name"`
					Health    string `json:"health"`
					LastError string `json:"lastError"`
				} `json:"rules"`
			} `json:"groups"`
		} `json:"data"`
	}
	if err := checker.getJSON(ctx, baseURL+"/api/v1/rules", &response); err != nil {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityWarning, Check: "rules", Summary: "Cannot query Prometheus rules", Detail: err.Error(), Verify: []string{"curl -s " + shellQuote(baseURL+"/api/v1/rules")}})
		return
	}
	failed := 0
	total := 0
	for _, group := range response.Data.Groups {
		for _, rule := range group.Rules {
			total++
			if rule.Health == "ok" || rule.Health == "" {
				continue
			}
			failed++
			report.Add(diagnostic.Finding{
				Severity:   diagnostic.SeverityWarning,
				Check:      "rules",
				Resource:   group.Name + "/" + rule.Name,
				Summary:    fmt.Sprintf("Prometheus rule is %s", rule.Health),
				Detail:     rule.LastError,
				Suggestion: "Correct the rule expression and verify referenced metrics and labels.",
				Verify:     []string{"curl -s " + shellQuote(baseURL+"/api/v1/rules")},
			})
		}
	}
	if failed == 0 {
		report.Add(diagnostic.Finding{Severity: diagnostic.SeverityInfo, Check: "rules", Summary: fmt.Sprintf("All %d rules are healthy", total), Verify: []string{"curl -s " + shellQuote(baseURL+"/api/v1/rules")}})
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (checker *Checker) getJSON(ctx context.Context, endpoint string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := checker.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 10<<20)).Decode(destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
