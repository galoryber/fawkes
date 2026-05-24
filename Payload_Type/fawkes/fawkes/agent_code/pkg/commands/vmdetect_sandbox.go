package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// sandboxCheck represents a single sandbox detection check result.
type sandboxCheck struct {
	Name       string `json:"name"`
	Category   string `json:"category"` // timing, hardware, environment, activity, network
	Suspicious bool   `json:"suspicious"`
	Score      int    `json:"score"` // 0-20 points per check
	Details    string `json:"details"`
}

// sandboxResult is the overall sandbox detection result.
type sandboxResult struct {
	TotalScore int            `json:"total_score"` // 0-100
	Verdict    string         `json:"verdict"`     // clean, suspicious, likely_sandbox, sandbox
	Checks     []sandboxCheck `json:"checks"`
}

// vmSandboxDetect runs all sandbox evasion checks and returns a scored result.
func vmSandboxDetect() sandboxResult {
	var checks []sandboxCheck

	checks = append(checks, sandboxCheckCPUCount())
	checks = append(checks, sandboxCheckSleepDrift())
	checks = append(checks, sandboxCheckHostname())
	checks = append(checks, sandboxCheckProcessCount())
	checks = append(checks, sandboxCheckUptime())
	checks = append(checks, sandboxCheckRAM())
	checks = append(checks, sandboxCheckDisk())
	checks = append(checks, sandboxCheckUsername())

	totalScore := 0
	for _, c := range checks {
		totalScore += c.Score
	}

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}

	verdict := "clean"
	switch {
	case totalScore >= 70:
		verdict = "sandbox"
	case totalScore >= 45:
		verdict = "likely_sandbox"
	case totalScore >= 20:
		verdict = "suspicious"
	}

	return sandboxResult{
		TotalScore: totalScore,
		Verdict:    verdict,
		Checks:     checks,
	}
}

// sandboxCheckCPUCount flags environments with very few CPUs.
func sandboxCheckCPUCount() sandboxCheck {
	cpus := runtime.NumCPU()
	suspicious := cpus < 2
	score := 0
	if cpus == 1 {
		score = 15
	}
	return sandboxCheck{
		Name:       "CPU Count",
		Category:   "hardware",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%d CPUs detected", cpus),
	}
}

// sandboxCheckSleepDrift measures if sleep is fast-forwarded (common in sandboxes).
func sandboxCheckSleepDrift() sandboxCheck {
	target := 500 * time.Millisecond
	start := time.Now()
	time.Sleep(target)
	elapsed := time.Since(start)

	// If sleep was significantly faster than expected, sandbox is likely
	drift := elapsed - target
	suspicious := false
	score := 0

	if elapsed < 400*time.Millisecond {
		// Sleep was fast-forwarded — strong sandbox indicator
		suspicious = true
		score = 20
	} else if elapsed < 450*time.Millisecond {
		suspicious = true
		score = 10
	}

	return sandboxCheck{
		Name:       "Sleep Timing",
		Category:   "timing",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("500ms sleep took %s (drift: %s)", elapsed.Round(time.Millisecond), drift.Round(time.Millisecond)),
	}
}

// sandboxCheckHostname checks for default/automated hostnames.
func sandboxCheckHostname() sandboxCheck {
	hostname, err := os.Hostname()
	if err != nil {
		return sandboxCheck{Name: "Hostname", Category: "environment", Details: "error: " + err.Error()}
	}

	suspicious := false
	score := 0
	lower := strings.ToLower(hostname)

	// Common sandbox/lab hostname patterns
	sandboxPatterns := []string{
		"sandbox", "malware", "virus", "sample", "test",
		"analysis", "cuckoo", "joe", "anubis", "threat",
		"payload", "detonation", "vbox", "vmware",
		"desktop-", "win-", "pc-", // very generic auto-generated names
	}

	for _, pattern := range sandboxPatterns {
		if strings.Contains(lower, pattern) {
			suspicious = true
			score = 10
			break
		}
	}

	// Very short hostnames or purely numeric hostnames
	if len(hostname) <= 3 || isNumericString(hostname) {
		suspicious = true
		if score < 5 {
			score = 5
		}
	}

	return sandboxCheck{
		Name:       "Hostname",
		Category:   "environment",
		Suspicious: suspicious,
		Score:      score,
		Details:    hostname,
	}
}

// sandboxCheckProcessCount flags environments with very few running processes.
func sandboxCheckProcessCount() sandboxCheck {
	count := countProcesses()
	suspicious := count > 0 && count < 50
	score := 0
	if count > 0 && count < 30 {
		score = 15
	} else if count > 0 && count < 50 {
		score = 10
	}

	details := fmt.Sprintf("%d processes running", count)
	if count == 0 {
		details = "unable to enumerate processes"
	}

	return sandboxCheck{
		Name:       "Process Count",
		Category:   "environment",
		Suspicious: suspicious,
		Score:      score,
		Details:    details,
	}
}

// sandboxCheckUsername checks for default/automated usernames.
func sandboxCheckUsername() sandboxCheck {
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	if username == "" {
		return sandboxCheck{Name: "Username", Category: "environment", Details: "unknown"}
	}

	suspicious := false
	score := 0
	lower := strings.ToLower(username)

	sandboxUsers := []string{
		"sandbox", "malware", "virus", "sample", "test",
		"analyst", "admin", "user", "john", "peter",
		"cuckoo", "joe", "currentuser", "hab1", "it-admin",
	}

	for _, pattern := range sandboxUsers {
		if lower == pattern {
			suspicious = true
			score = 10
			break
		}
	}

	return sandboxCheck{
		Name:       "Username",
		Category:   "environment",
		Suspicious: suspicious,
		Score:      score,
		Details:    username,
	}
}

// isNumericString returns true if s contains only digits.
func isNumericString(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// formatSandboxResult formats the sandbox result for display.
func formatSandboxResult(result sandboxResult) string {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting result: %v", err)
	}
	return string(jsonBytes)
}
