package amtool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewbytecoder/kdig/pkg/diagnostic"
	corev1 "k8s.io/api/core/v1"
)

type alert struct {
	Labels map[string]string `json:"labels"`
	Status struct {
		State string `json:"state"`
	} `json:"status"`
}

type silence struct {
	ID     string `json:"id"`
	Status struct {
		State string `json:"state"`
	} `json:"status"`
}

func (checker *Checker) collectFromPod(ctx context.Context, report *diagnostic.Report, pod corev1.Pod) podResult {
	result := podResult{pod: pod.Name}
	if !hasContainer(pod, checker.options.Container) {
		return result
	}
	resource := diagnostic.Resource("pod", pod.Namespace, pod.Name)

	version, versionErr := checker.run(ctx, pod.Name, "--version")
	if versionErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "amtool-version", versionErr, "--version"))
		return result
	}
	report.Add(diagnostic.Finding{
		Severity: diagnostic.SeverityInfo,
		Check:    "amtool-version",
		Resource: resource,
		Summary:  firstLine(version),
		Verify:   checker.amtoolVerify(pod.Name, "--version"),
	})

	alertsOutput, alertsErr := checker.run(ctx, pod.Name, "-o", "json", "alert", "query")
	if alertsErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "alerts", alertsErr, "-o", "json", "alert", "query"))
	} else {
		alerts, parseErr := parseAlerts(alertsOutput)
		if parseErr != nil {
			report.Add(checker.parseFailure(pod.Name, resource, "alerts", parseErr, alertsOutput, "-o", "json", "alert", "query"))
		} else {
			result.alertCount = len(alerts)
			result.alertsCollected = true
			result.alertDigest = alertDigest(alerts)
			checker.addAlertFindings(report, resource, alerts)
		}
	}

	extendedOutput, extendedErr := checker.run(ctx, pod.Name, "-o", "extended", "alert", "query")
	if extendedErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "alerts-extended", extendedErr, "-o", "extended", "alert", "query"))
	} else {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "alerts-extended",
			Resource: resource,
			Summary:  "Collected extended alert details",
			Detail:   truncateOutput(extendedOutput),
			Verify:   checker.amtoolVerify(pod.Name, "-o", "extended", "alert", "query"),
		})
	}

	configOutput, configErr := checker.run(ctx, pod.Name, "config", "show")
	if configErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "configuration", configErr, "config", "show"))
	} else {
		result.configOutput = normalizeConfig(configOutput)
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "configuration",
			Resource: resource,
			Summary:  "Loaded Alertmanager configuration via amtool",
			Detail:   configSummary(configOutput) + "\n\nLoaded configuration (sensitive values redacted):\n" + truncateOutput(redactConfig(configOutput)),
			Verify:   checker.amtoolVerify(pod.Name, "config", "show"),
		})
	}

	routesOutput, routesErr := checker.run(ctx, pod.Name, "config", "routes", "show")
	if routesErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "routes", routesErr, "config", "routes", "show"))
	} else {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "routes",
			Resource: resource,
			Summary:  "Collected Alertmanager routing tree",
			Detail:   truncateOutput(routesOutput),
			Verify:   checker.amtoolVerify(pod.Name, "config", "routes", "show"),
		})
	}

	silencesOutput, silencesErr := checker.run(ctx, pod.Name, "-o", "json", "silence", "query")
	if silencesErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "silences", silencesErr, "-o", "json", "silence", "query"))
	} else {
		silences, parseErr := parseSilences(silencesOutput)
		if parseErr != nil {
			report.Add(checker.parseFailure(pod.Name, resource, "silences", parseErr, silencesOutput, "-o", "json", "silence", "query"))
		} else {
			active := 0
			pending := 0
			for _, item := range silences {
				switch strings.ToLower(item.Status.State) {
				case "active":
					active++
				case "pending":
					pending++
				}
			}
			report.Add(diagnostic.Finding{
				Severity: diagnostic.SeverityInfo,
				Check:    "silences",
				Resource: resource,
				Summary:  fmt.Sprintf("Found %d silences: %d active, %d pending", len(silences), active, pending),
				Verify:   checker.amtoolVerify(pod.Name, "silence", "query"),
			})
		}
	}

	clusterOutput, clusterErr := checker.run(ctx, pod.Name, "cluster", "show")
	if clusterErr != nil {
		report.Add(checker.commandFailure(pod.Name, resource, "cluster", clusterErr, "cluster", "show"))
	} else {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "cluster",
			Resource: resource,
			Summary:  "Collected Alertmanager cluster status",
			Detail:   truncateOutput(clusterOutput),
			Verify:   checker.amtoolVerify(pod.Name, "cluster", "show"),
		})
	}
	return result
}

func (checker *Checker) amtoolVerify(pod string, arguments ...string) []string {
	if pod == "" {
		return nil
	}
	command := []string{
		"kubectl", "exec", "-n", checker.options.Namespace, pod,
		"-c", checker.options.Container, "--", "amtool",
		"--alertmanager.url=" + checker.options.AlertmanagerURL,
	}
	command = append(command, arguments...)
	return []string{
		"kubectl get pod " + pod + " -n " + checker.options.Namespace + " -o wide",
		strings.Join(command, " "),
	}
}

func resourcePodName(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) >= 3 && parts[0] == "pod" {
		return parts[2]
	}
	return ""
}

func (checker *Checker) run(ctx context.Context, pod string, arguments ...string) (string, error) {
	command := []string{"amtool", "--alertmanager.url=" + checker.options.AlertmanagerURL}
	command = append(command, arguments...)
	stdout, stderr, err := checker.clients.PodExec.Exec(
		ctx,
		checker.options.Namespace,
		pod,
		checker.options.Container,
		command,
	)
	if err != nil {
		detail := strings.TrimSpace(stderr)
		if detail != "" {
			detail += ": "
		}
		return stdout, fmt.Errorf("%s%w", detail, err)
	}
	return stdout, nil
}

func (checker *Checker) addAlertFindings(report *diagnostic.Report, resource string, alerts []alert) {
	byName := make(map[string]int)
	bySeverity := make(map[string]int)
	actionable := 0
	critical := 0
	for _, item := range alerts {
		name := item.Labels["alertname"]
		if name == "" {
			name = "<unknown>"
		}
		byName[name]++
		severity := item.Labels["severity"]
		if severity == "" {
			severity = "<unset>"
		}
		bySeverity[severity]++
		if !strings.EqualFold(name, "Watchdog") {
			actionable++
			switch strings.ToLower(severity) {
			case "critical", "emergency", "fatal":
				critical++
			}
		}
	}

	severity := diagnostic.SeverityInfo
	if critical > 0 {
		severity = diagnostic.SeverityCritical
	} else if actionable > 0 {
		severity = diagnostic.SeverityWarning
	}
	report.Add(diagnostic.Finding{
		Severity: severity,
		Check:    "alerts",
		Resource: resource,
		Summary:  fmt.Sprintf("Found %d active alerts, %d actionable, %d critical", len(alerts), actionable, critical),
		Detail:   "By severity: " + formatCounts(bySeverity) + "\nBy alert name: " + formatCounts(byName),
		Verify:   checker.amtoolVerify(resourcePodName(resource), "alert", "query"),
	})
}

func (checker *Checker) compareReplicas(report *diagnostic.Report, results []podResult) {
	if len(results) < 2 {
		return
	}
	alertCounts := make(map[int][]string)
	alertDigests := make(map[string][]string)
	configDigests := make(map[string][]string)
	for _, result := range results {
		if result.alertsCollected {
			alertCounts[result.alertCount] = append(alertCounts[result.alertCount], result.pod)
			alertDigests[result.alertDigest] = append(alertDigests[result.alertDigest], result.pod)
		}
		if result.configOutput != "" {
			digest := sha256.Sum256([]byte(result.configOutput))
			configDigests[hex.EncodeToString(digest[:8])] = append(configDigests[hex.EncodeToString(digest[:8])], result.pod)
		}
	}
	if len(alertDigests) > 1 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityWarning,
			Check:      "replica-consistency",
			Summary:    "Alertmanager replicas report different active alert snapshots",
			Detail:     formatStringGroups(alertDigests) + "\n" + formatIntGroups(alertCounts),
			Suggestion: "Check cluster gossip health, Prometheus delivery targets, and network connectivity between Alertmanager peers.",
		})
	}
	if len(configDigests) > 1 {
		report.Add(diagnostic.Finding{
			Severity:   diagnostic.SeverityCritical,
			Check:      "replica-consistency",
			Summary:    "Alertmanager replicas have different loaded configurations",
			Detail:     formatStringGroups(configDigests),
			Suggestion: "Check config-reloader logs, generated Secrets, and StatefulSet volume mounts.",
		})
	} else if len(configDigests) == 1 {
		report.Add(diagnostic.Finding{
			Severity: diagnostic.SeverityInfo,
			Check:    "replica-consistency",
			Summary:  "Alertmanager replicas have consistent loaded configurations",
			Detail:   formatStringGroups(configDigests),
		})
	}
}

func parseAlerts(output string) ([]alert, error) {
	var alerts []alert
	if err := json.Unmarshal([]byte(output), &alerts); err != nil {
		return nil, fmt.Errorf("decode amtool alert JSON: %w", err)
	}
	return alerts, nil
}

func parseSilences(output string) ([]silence, error) {
	var silences []silence
	if err := json.Unmarshal([]byte(output), &silences); err != nil {
		return nil, fmt.Errorf("decode amtool silence JSON: %w", err)
	}
	return silences, nil
}

func alertDigest(alerts []alert) string {
	items := make([]string, 0, len(alerts))
	for _, item := range alerts {
		labelsJSON, _ := json.Marshal(item.Labels)
		items = append(items, string(labelsJSON)+"|"+item.Status.State)
	}
	sort.Strings(items)
	digest := sha256.Sum256([]byte(strings.Join(items, "\n")))
	return hex.EncodeToString(digest[:8])
}

func (checker *Checker) commandFailure(pod string, resource string, check string, err error, arguments ...string) diagnostic.Finding {
	return diagnostic.Finding{
		Severity:   diagnostic.SeverityWarning,
		Check:      check,
		Resource:   resource,
		Summary:    "amtool command failed",
		Detail:     err.Error(),
		Suggestion: "Verify amtool exists in the selected container, the local Alertmanager URL is correct, and pods/exec is allowed.",
		Verify:     checker.amtoolVerify(pod, arguments...),
	}
}

func (checker *Checker) parseFailure(pod string, resource string, check string, err error, output string, arguments ...string) diagnostic.Finding {
	return diagnostic.Finding{
		Severity: diagnostic.SeverityWarning,
		Check:    check,
		Resource: resource,
		Summary:  "Cannot parse amtool output",
		Detail:   err.Error() + "\n" + truncateOutput(output),
		Verify:   checker.amtoolVerify(pod, arguments...),
	}
}

func firstLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "amtool is available"
	}
	return lines[0]
}

func configSummary(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	receivers := 0
	inhibitRules := 0
	templates := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "- name:") && strings.HasPrefix(line, "-"):
			receivers++
		case strings.HasPrefix(trimmed, "- source_match") || strings.HasPrefix(trimmed, "- source_matchers"):
			inhibitRules++
		case strings.HasPrefix(trimmed, "- ") && strings.Contains(strings.ToLower(trimmed), ".tmpl"):
			templates++
		}
	}
	digest := sha256.Sum256([]byte(normalizeConfig(output)))
	return fmt.Sprintf(
		"SHA256: %s\nLines: %d\nDetected receivers: %d\nDetected inhibit rules: %d\nDetected templates: %d",
		hex.EncodeToString(digest[:8]),
		len(lines),
		receivers,
		inhibitRules,
		templates,
	)
}

func normalizeConfig(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return strings.Join(lines, "\n")
}

func redactConfig(output string) string {
	lines := strings.Split(output, "\n")
	for index, line := range lines {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		key = strings.TrimSpace(strings.TrimPrefix(key, "-"))
		if !isSensitiveConfigKey(key) {
			continue
		}
		lines[index] = line[:colon+1] + " <redacted>"
	}
	return strings.Join(lines, "\n")
}

func isSensitiveConfigKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, fragment := range []string{
		"password",
		"secret",
		"token",
		"api_key",
		"api_url",
		"webhook_url",
		"routing_key",
		"service_key",
		"credentials",
		"authorization",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	if normalized == "url" {
		return true
	}
	return false
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(values, ", ")
}

func formatIntGroups(groups map[int][]string) string {
	keys := make([]int, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		sort.Strings(groups[key])
		values = append(values, fmt.Sprintf("%d alerts: %s", key, strings.Join(groups[key], ", ")))
	}
	return strings.Join(values, "\n")
}

func formatStringGroups(groups map[string][]string) string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		sort.Strings(groups[key])
		values = append(values, fmt.Sprintf("%s: %s", key, strings.Join(groups[key], ", ")))
	}
	return strings.Join(values, "\n")
}

func truncateOutput(output string) string {
	const maxLength = 12000
	trimmed := strings.TrimSpace(output)
	runes := []rune(trimmed)
	if len(runes) <= maxLength {
		return trimmed
	}
	return string(runes[:maxLength]) + "\n... output truncated"
}
