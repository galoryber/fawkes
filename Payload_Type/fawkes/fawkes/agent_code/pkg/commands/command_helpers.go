package commands

// command_helpers.go contains pure helper functions extracted from
// platform-specific command files for cross-platform testing.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// --- DPAPI helpers (from dpapi.go) ---

// dpapiIsPrintable checks if a byte slice contains printable ASCII/UTF-8
func dpapiIsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// isGUID checks if a string looks like a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// extractXMLTag extracts the text content of a simple XML tag
func extractXMLTag(xml, tag string) string {
	start := strings.Index(xml, "<"+tag+">")
	if start == -1 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xml[start:], "</"+tag+">")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

// --- ETW helpers (from etw.go) ---

// classifySessionSecurity classifies an ETW session name by security relevance
func classifySessionSecurity(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "defender") || strings.Contains(lower, "antimalware"):
		return "!! DEFENDER/AV"
	case strings.Contains(lower, "sysmon"):
		return "!! SYSMON"
	case strings.Contains(lower, "edr") || strings.Contains(lower, "sentinel") ||
		strings.Contains(lower, "crowdstrike") || strings.Contains(lower, "carbon"):
		return "!! EDR"
	case strings.Contains(lower, "security"):
		return "! Security"
	case strings.Contains(lower, "audit"):
		return "! Audit"
	case strings.Contains(lower, "etw") || strings.Contains(lower, "eventlog"):
		return "Telemetry"
	case strings.Contains(lower, "kernel"):
		return "Kernel"
	case strings.Contains(lower, "diagtrack") || strings.Contains(lower, "autologger"):
		return "Diagnostics"
	default:
		return ""
	}
}

// --- BITS helpers (from bits.go) ---

// bitsFormatBytes formats byte counts as human-readable strings
func bitsFormatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// bitsEllipsis truncates a string with ellipsis if it exceeds max length
func bitsEllipsis(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// --- Credential Manager helpers (from credman.go) ---

// Credential type constants
const (
	credTypeGeneric           = 1
	credTypeDomainPassword    = 2
	credTypeDomainCertificate = 3
	credTypeDomainVisible     = 4
)

// isPrintable checks if a string contains only printable characters
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) > 0
}

// credTypeName maps Windows credential type codes to display names
func credTypeName(t uint32) string {
	switch t {
	case credTypeGeneric:
		return "Generic"
	case credTypeDomainPassword:
		return "Domain Password"
	case credTypeDomainCertificate:
		return "Domain Certificate"
	case credTypeDomainVisible:
		return "Domain Visible Password"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

// credPersistName maps credential persistence scope codes to names
func credPersistName(p uint32) string {
	switch p {
	case 1:
		return "Session"
	case 2:
		return "Local Machine"
	case 3:
		return "Enterprise"
	default:
		return fmt.Sprintf("Unknown (%d)", p)
	}
}

// --- Amcache/Shimcache helpers (from amcache.go) ---

// decodeUTF16LEShim decodes a UTF-16LE byte slice to a Go string
func decodeUTF16LEShim(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Remove trailing null
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
