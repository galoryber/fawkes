package agentfunctions

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// runYARAScan runs YARA rules against a built payload and returns a formatted report.
// This is informational only — it never causes a build failure.
func runYARAScan(payloadPath string) string {
	rulesPath := "./yara_rules/fawkes_scan.yar"

	// Check if YARA is available
	if _, err := exec.LookPath("yara"); err != nil {
		return "YARA not installed — skipping detection scan"
	}

	// Check if rules file exists
	if _, err := os.Stat(rulesPath); err != nil {
		return fmt.Sprintf("YARA rules not found at %s — skipping detection scan", rulesPath)
	}

	// Check if payload exists
	fi, err := os.Stat(payloadPath)
	if err != nil {
		return fmt.Sprintf("Payload not found at %s — skipping YARA scan", payloadPath)
	}

	// Run YARA with metadata output
	cmd := exec.Command("yara", "-s", "-m", rulesPath, payloadPath)
	var yaraOut bytes.Buffer
	var yaraErr bytes.Buffer
	cmd.Stdout = &yaraOut
	cmd.Stderr = &yaraErr

	scanErr := cmd.Run()

	var report strings.Builder
	report.WriteString(fmt.Sprintf("=== YARA Detection Scan ===\n"))
	report.WriteString(fmt.Sprintf("Payload: %s (%d bytes)\n", filepath.Base(payloadPath), fi.Size()))
	report.WriteString(fmt.Sprintf("Rules:   %s\n\n", rulesPath))

	if yaraErr.Len() > 0 {
		report.WriteString(fmt.Sprintf("YARA warnings: %s\n", yaraErr.String()))
	}

	output := strings.TrimSpace(yaraOut.String())
	if output == "" && scanErr == nil {
		report.WriteString("Result: CLEAN — no detection rules matched\n")
		return report.String()
	}

	if scanErr != nil && output == "" {
		report.WriteString(fmt.Sprintf("YARA scan error (non-fatal): %v\n", scanErr))
		return report.String()
	}

	// Parse and format matches
	lines := strings.Split(output, "\n")
	matchCount := 0
	var matches []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// YARA output with -m: "RuleName [meta1=val1,meta2=val2] /path/to/file"
		// Without -s match lines start with "0x" (string match offset)
		if strings.HasPrefix(line, "0x") {
			continue // Skip string match detail lines
		}
		matchCount++
		// Extract rule name (first field before space or bracket)
		parts := strings.SplitN(line, " ", 2)
		ruleName := parts[0]
		meta := ""
		if len(parts) > 1 {
			// Extract metadata between brackets
			if idx := strings.Index(parts[1], "["); idx >= 0 {
				if endIdx := strings.Index(parts[1], "]"); endIdx > idx {
					meta = parts[1][idx+1 : endIdx]
				}
			}
		}
		matches = append(matches, fmt.Sprintf("  [%d] %s", matchCount, ruleName))
		if meta != "" {
			matches = append(matches, fmt.Sprintf("      %s", meta))
		}
	}

	if matchCount == 0 {
		report.WriteString("Result: CLEAN — no detection rules matched\n")
	} else {
		report.WriteString(fmt.Sprintf("Result: %d rule(s) matched\n\n", matchCount))
		report.WriteString("Matches:\n")
		report.WriteString(strings.Join(matches, "\n"))
		report.WriteString("\n\nNote: These are informational — consider enabling garble, obfuscate_strings, or -trimpath to reduce detections.")
	}

	return report.String()
}

// runEntropyScan runs the ent command against a built payload and returns a formatted report.
// This is informational only — it never causes a build failure.
func runEntropyScan(payloadPath string) string {
	// Check if ent is available
	if _, err := exec.LookPath("ent"); err != nil {
		return "ent not installed — skipping entropy analysis"
	}

	// Check if payload exists
	fi, err := os.Stat(payloadPath)
	if err != nil {
		return fmt.Sprintf("Payload not found at %s — skipping entropy analysis", payloadPath)
	}

	// Run ent
	cmd := exec.Command("ent", payloadPath)
	var entOut bytes.Buffer
	var entErr bytes.Buffer
	cmd.Stdout = &entOut
	cmd.Stderr = &entErr

	scanErr := cmd.Run()

	var report strings.Builder
	report.WriteString("=== Entropy Analysis ===\n")
	report.WriteString(fmt.Sprintf("Payload: %s (%d bytes / %.2f MB)\n\n", filepath.Base(payloadPath), fi.Size(), float64(fi.Size())/(1024*1024)))

	if scanErr != nil {
		report.WriteString(fmt.Sprintf("ent error (non-fatal): %v\n", scanErr))
		if entErr.Len() > 0 {
			report.WriteString(fmt.Sprintf("stderr: %s\n", entErr.String()))
		}
		return report.String()
	}

	output := strings.TrimSpace(entOut.String())
	if output == "" {
		report.WriteString("No output from ent\n")
		return report.String()
	}

	report.WriteString(output)
	report.WriteString("\n\n")

	// Parse entropy value and add assessment
	report.WriteString(formatEntropyAssessment(output))

	return report.String()
}

// formatEntropyAssessment parses ent output and adds an opsec assessment.
func formatEntropyAssessment(entOutput string) string {
	// Extract entropy value from "Entropy = X.XXXXXX bits per byte."
	var entropy float64
	for _, line := range strings.Split(entOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Entropy = ") {
			// Parse "Entropy = 7.999822 bits per byte."
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if val, err := strconv.ParseFloat(parts[2], 64); err == nil {
					entropy = val
				}
			}
			break
		}
	}

	if entropy == 0 {
		return ""
	}

	var assessment strings.Builder
	assessment.WriteString("--- Opsec Assessment ---\n")
	if entropy >= 7.9 {
		assessment.WriteString(fmt.Sprintf("Entropy: %.4f — VERY HIGH (packed/encrypted signature)\n", entropy))
		assessment.WriteString("Recommendation: Consider using inflate_bytes build parameter to lower entropy.\n")
		assessment.WriteString("  Example: inflate_bytes=0x00 inflate_count=500000 adds ~500KB of zero bytes.\n")
	} else if entropy >= 7.5 {
		assessment.WriteString(fmt.Sprintf("Entropy: %.4f — HIGH (typical for compiled Go binaries)\n", entropy))
		assessment.WriteString("Note: Go binaries naturally have high entropy due to static linking.\n")
	} else if entropy >= 6.0 {
		assessment.WriteString(fmt.Sprintf("Entropy: %.4f — MODERATE (good for evasion)\n", entropy))
	} else {
		assessment.WriteString(fmt.Sprintf("Entropy: %.4f — LOW (normal executable range)\n", entropy))
	}

	return assessment.String()
}
