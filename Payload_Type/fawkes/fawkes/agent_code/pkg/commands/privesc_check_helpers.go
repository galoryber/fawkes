package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isUnquotedServicePath checks if a service path has spaces but is not quoted
func isUnquotedServicePath(binPath string) bool {
	// Skip paths that start with a quote
	if strings.HasPrefix(binPath, `"`) {
		return false
	}
	// Skip svchost-style paths (system services)
	lower := strings.ToLower(binPath)
	if strings.Contains(lower, "svchost") || strings.Contains(lower, "system32") {
		return false
	}
	// Extract the executable path (before any arguments)
	exePath := extractExePath(binPath)
	if exePath == "" {
		return false
	}
	// Check if the path contains spaces
	return strings.Contains(exePath, " ")
}

// extractExePath extracts the executable path from a service binary path
// which may include arguments
func extractExePath(binPath string) string {
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		return ""
	}

	// If quoted, extract between quotes
	if strings.HasPrefix(binPath, `"`) {
		end := strings.Index(binPath[1:], `"`)
		if end == -1 {
			return binPath[1:]
		}
		return binPath[1 : end+1]
	}

	// Not quoted — find the first path that exists as a file
	// Try progressively longer segments
	parts := strings.Split(binPath, " ")
	candidate := ""
	for i, part := range parts {
		if i == 0 {
			candidate = part
		} else {
			candidate += " " + part
		}
		// Check if this candidate exists as a file
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		// Try with .exe appended
		if !strings.HasSuffix(strings.ToLower(candidate), ".exe") {
			if _, err := os.Stat(candidate + ".exe"); err == nil {
				return candidate + ".exe"
			}
		}
	}

	// Fall back to the first space-delimited token
	if idx := strings.Index(binPath, " "); idx != -1 {
		return binPath[:idx]
	}
	return binPath
}

func startTypeString(st uint32) string {
	switch st {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Auto"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return fmt.Sprintf("Unknown(%d)", st)
	}
}

func isFileReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func isDirWritable(dir string) bool {
	tmpFile := filepath.Join(dir, ".fawkes_privesc_test")
	f, err := os.Create(tmpFile)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(tmpFile)
	return true
}
