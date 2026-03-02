package commands

import (
	"fmt"
	"strings"
)

// --- LaunchAgent plist helpers ---

// macBuildPlist generates a macOS plist XML for a LaunchAgent or LaunchDaemon.
// Pure function — no I/O, no system calls.
func macBuildPlist(label string, programArgs []string, runAt string, interval int) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, arg := range programArgs {
		sb.WriteString("\t\t<string>" + macXmlEscape(arg) + "</string>\n")
	}
	sb.WriteString("\t</array>\n")

	// RunAtLoad — start when loaded (login or boot)
	sb.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")

	// KeepAlive — restart if it dies
	sb.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")

	// StartInterval — periodic execution
	if interval > 0 {
		sb.WriteString(fmt.Sprintf("\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", interval))
	}

	// StartCalendarInterval — cron-like scheduling
	if runAt != "" {
		sb.WriteString(macBuildCalendarInterval(runAt))
	}

	// StandardOutPath and StandardErrorPath — hide output
	sb.WriteString("\t<key>StandardOutPath</key>\n\t<string>/dev/null</string>\n")
	sb.WriteString("\t<key>StandardErrorPath</key>\n\t<string>/dev/null</string>\n")

	sb.WriteString("</dict>\n</plist>\n")
	return sb.String()
}

// macXmlEscape escapes special XML characters in plist values.
func macXmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// macBuildCalendarInterval converts a simple time string to plist CalendarInterval format.
// Supports: "HH:MM" (daily at time), "weekday HH:MM" (e.g., "1 09:00" = Monday at 9am).
func macBuildCalendarInterval(runAt string) string {
	parts := strings.Fields(runAt)
	var sb strings.Builder
	sb.WriteString("\t<key>StartCalendarInterval</key>\n\t<dict>\n")

	if len(parts) == 2 {
		// "weekday HH:MM"
		sb.WriteString(fmt.Sprintf("\t\t<key>Weekday</key>\n\t\t<integer>%s</integer>\n", parts[0]))
		timeParts := strings.Split(parts[1], ":")
		if len(timeParts) == 2 {
			sb.WriteString(fmt.Sprintf("\t\t<key>Hour</key>\n\t\t<integer>%s</integer>\n", timeParts[0]))
			sb.WriteString(fmt.Sprintf("\t\t<key>Minute</key>\n\t\t<integer>%s</integer>\n", timeParts[1]))
		}
	} else if len(parts) == 1 {
		// "HH:MM"
		timeParts := strings.Split(parts[0], ":")
		if len(timeParts) == 2 {
			sb.WriteString(fmt.Sprintf("\t\t<key>Hour</key>\n\t\t<integer>%s</integer>\n", timeParts[0]))
			sb.WriteString(fmt.Sprintf("\t\t<key>Minute</key>\n\t\t<integer>%s</integer>\n", timeParts[1]))
		}
	}

	sb.WriteString("\t</dict>\n")
	return sb.String()
}

// --- Keychain helpers ---

// macBuildFilterArgs builds security CLI filter arguments from optional fields.
func macBuildFilterArgs(serverOrService, account, label string) []string {
	var args []string
	if serverOrService != "" {
		args = append(args, "-s", serverOrService)
	}
	if account != "" {
		args = append(args, "-a", account)
	}
	if label != "" {
		args = append(args, "-l", label)
	}
	return args
}

// macIsItemNotFound checks if security CLI output indicates no keychain item was found.
func macIsItemNotFound(output string) bool {
	return strings.Contains(output, "could not be found") ||
		strings.Contains(output, "SecKeychainSearchCopyNext")
}

// --- privesc-check TCC helpers ---

// macTCCServiceFlag returns a human-readable flag for high-value TCC service names.
func macTCCServiceFlag(service string) string {
	switch service {
	case "kTCCServiceAccessibility":
		return " [!] Accessibility — can control UI, inject keystrokes"
	case "kTCCServiceScreenCapture":
		return " [!] Screen Capture"
	case "kTCCServiceSystemPolicyAllFiles":
		return " [!] Full Disk Access"
	case "kTCCServiceMicrophone":
		return " [!] Microphone Access"
	case "kTCCServiceCamera":
		return " [!] Camera Access"
	default:
		return ""
	}
}
