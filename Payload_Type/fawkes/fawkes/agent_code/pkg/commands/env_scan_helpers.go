package commands

import (
	"fmt"
	"sort"
	"strings"
)

// envScanResult represents a single sensitive environment variable finding.
type envScanResult struct {
	PID      int    `json:"pid"`
	Process  string `json:"process"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
	Category string `json:"category"`
}

// sensitiveEnvPattern defines a pattern for matching sensitive environment variable names.
type sensitiveEnvPattern struct {
	Pattern  string // substring to match (case-insensitive)
	Category string // category for display
}

// sensitiveEnvPatterns defines patterns that indicate potentially sensitive environment variables.
// IMPORTANT: More specific patterns MUST come before generic ones — first match wins.
var sensitiveEnvPatterns = []sensitiveEnvPattern{
	// Cloud provider credentials (specific, before generic SECRET/PASSWORD/ACCESS_KEY)
	{"AWS_SECRET", "AWS Credential"},
	{"AWS_ACCESS", "AWS Credential"},
	{"AWS_SESSION", "AWS Session"},
	{"AZURE_CLIENT_SECRET", "Azure Credential"},
	{"AZURE_TENANT", "Azure Config"},
	{"GOOGLE_APPLICATION_CREDENTIALS", "GCP Credential"},
	{"GCP_SERVICE_ACCOUNT", "GCP Credential"},

	// Database and service connections (specific, before generic PASSWORD)
	{"DATABASE_URL", "Database URL"},
	{"DB_PASSWORD", "Database Password"},
	{"DB_PASS", "Database Password"},
	{"REDIS_URL", "Redis URL"},
	{"REDIS_PASSWORD", "Redis Password"},
	{"MONGO_URI", "MongoDB URI"},
	{"MYSQL_PASSWORD", "MySQL Password"},
	{"POSTGRES_PASSWORD", "PostgreSQL Password"},
	{"CONNECTION_STRING", "Connection String"},

	// Container and orchestration (specific, before generic PASSWORD)
	{"DOCKER_PASSWORD", "Docker Credential"},
	{"REGISTRY_PASSWORD", "Registry Credential"},
	{"KUBECONFIG", "Kubernetes Config"},

	// Messaging and notifications (specific, before generic SECRET/PASSWORD)
	{"SLACK_TOKEN", "Slack Token"},
	{"SLACK_WEBHOOK", "Slack Webhook"},
	{"WEBHOOK_SECRET", "Webhook Secret"},
	{"SMTP_PASSWORD", "SMTP Password"},

	// CI/CD and VCS (specific tokens)
	{"GITHUB_TOKEN", "GitHub Token"},
	{"GITLAB_TOKEN", "GitLab Token"},
	{"NPM_TOKEN", "NPM Token"},
	{"PYPI_TOKEN", "PyPI Token"},
	{"NUGET_API", "NuGet Token"},
	{"SONAR_TOKEN", "SonarQube Token"},

	// Encryption and signing (specific, before generic SECRET)
	{"SIGNING_KEY", "Signing Key"},
	{"JWT_SECRET", "JWT Secret"},

	// API keys and tokens
	{"API_KEY", "API Key"},
	{"APIKEY", "API Key"},
	{"API_TOKEN", "API Token"},
	{"ACCESS_KEY", "Access Key"},
	{"ACCESS_TOKEN", "Access Token"},
	{"AUTH_TOKEN", "Auth Token"},
	{"BEARER", "Bearer Token"},

	// Generic secrets and passwords (last — catch-all)
	{"SECRET", "Secret"},
	{"PASSWORD", "Password"},
	{"PASSWD", "Password"},
	{"CREDENTIAL", "Credential"},
	{"PRIVATE_KEY", "Private Key"},
	{"ENCRYPTION_KEY", "Encryption Key"},
	{"HMAC", "HMAC Key"},
	{"SALT", "Crypto Salt"},
	{"CIPHER", "Cipher Config"},
}

// parseEnvironBlock parses a null-separated environment block (as read from /proc/<pid>/environ)
// into key=value pairs.
func parseEnvironBlock(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	var result []string
	for _, entry := range strings.Split(string(data), "\x00") {
		entry = strings.TrimSpace(entry)
		if entry != "" && strings.Contains(entry, "=") {
			result = append(result, entry)
		}
	}
	return result
}

// classifyEnvVar checks if an environment variable name matches any sensitive pattern
// and returns the category. Returns empty string if not sensitive.
func classifyEnvVar(name string) string {
	upper := strings.ToUpper(name)
	for _, p := range sensitiveEnvPatterns {
		if strings.Contains(upper, p.Pattern) {
			return p.Category
		}
	}
	return ""
}

// filterSensitiveVars scans a list of key=value environment variables and returns
// only those matching sensitive patterns.
func filterSensitiveVars(envVars []string, pid int, processName string) []envScanResult {
	var results []envScanResult
	for _, kv := range envVars {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		value := parts[1]

		category := classifyEnvVar(name)
		if category != "" {
			results = append(results, envScanResult{
				PID:      pid,
				Process:  processName,
				Variable: name,
				Value:    redactValue(value),
				Category: category,
			})
		}
	}
	return results
}

// redactValue partially redacts a sensitive value for safe display.
// Shows first 4 and last 4 characters for values > 12 chars.
func redactValue(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// formatEnvScanResults formats scan results into readable output.
func formatEnvScanResults(results []envScanResult, totalProcesses, accessibleProcesses int) string {
	var sb strings.Builder

	sb.WriteString("=== Process Environment Variable Scan ===\n\n")
	sb.WriteString(fmt.Sprintf("Processes scanned: %d / %d total\n", accessibleProcesses, totalProcesses))
	sb.WriteString(fmt.Sprintf("Sensitive variables found: %d\n\n", len(results)))

	if len(results) == 0 {
		sb.WriteString("No sensitive environment variables detected.\n")
		return sb.String()
	}

	// Group by category
	grouped := make(map[string][]envScanResult)
	var categories []string
	for _, r := range results {
		if _, exists := grouped[r.Category]; !exists {
			categories = append(categories, r.Category)
		}
		grouped[r.Category] = append(grouped[r.Category], r)
	}
	sort.Strings(categories)

	for _, cat := range categories {
		catResults := grouped[cat]
		sb.WriteString(fmt.Sprintf("--- %s (%d) ---\n", cat, len(catResults)))
		for _, r := range catResults {
			sb.WriteString(fmt.Sprintf("  [PID %d] %s: %s = %s\n", r.PID, r.Process, r.Variable, r.Value))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
