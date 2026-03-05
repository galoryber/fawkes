package commands

// format_helpers.go provides unified formatting utility functions used across
// multiple command implementations. These consolidate duplicate functions that
// were previously scattered across df.go, enum_tokens.go, cloudmetadata.go,
// command_helpers.go, and find.go.

import "fmt"

// truncStr truncates a string to max characters, appending "..." if truncated.
// Consolidates: truncStr (df.go), truncateStr (enum_tokens.go),
// tsTruncateOwner (command_helpers.go), bitsEllipsis (command_helpers.go).
func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// truncate returns the first n characters of a string without ellipsis.
// Used when a hard cutoff is preferred over an ellipsis indicator.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// formatBytes formats a uint64 byte count as a human-readable string (KB, MB, GB, TB).
// Consolidates: bitsFormatBytes, formatDumpSize, formatRegSaveSize, formatScanSize,
// formatEvtLogSize, formatModuleSize, hashFormatSize, statFormatSize.
func formatBytes(b uint64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(1<<40))
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

// formatFileSize formats an int64 byte count as a human-readable string.
// Convenience wrapper around formatBytes for signed size values.
// Consolidates: formatFileSize (find.go).
func formatFileSize(bytes int64) string {
	if bytes < 0 {
		return "0 B"
	}
	return formatBytes(uint64(bytes))
}
