package commands

import "strings"

// stripPathQuotes strips surrounding whitespace and quotes from a path so that
// paths like "C:\Program Data" resolve to C:\Program Data.
func stripPathQuotes(path string) string {
	path = strings.TrimSpace(path)
	if len(path) >= 2 {
		if (path[0] == '"' && path[len(path)-1] == '"') ||
			(path[0] == '\'' && path[len(path)-1] == '\'') {
			path = path[1 : len(path)-1]
		}
	}
	return path
}
