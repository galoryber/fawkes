package agentfunctions

import "strings"

// extractQuotedArg extracts the next argument from a string, respecting
// surrounding quotes so that paths with spaces like "C:\Program Files\foo.txt"
// are treated as a single argument. Returns the extracted argument and the
// remaining unparsed string.
func extractQuotedArg(s string) (arg, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' {
		end := strings.Index(s[1:], "\"")
		if end >= 0 {
			return s[1 : end+1], s[end+2:]
		}
		return s[1:], ""
	}
	if s[0] == '\'' {
		end := strings.Index(s[1:], "'")
		if end >= 0 {
			return s[1 : end+1], s[end+2:]
		}
		return s[1:], ""
	}
	end := strings.IndexByte(s, ' ')
	if end >= 0 {
		return s[:end], s[end+1:]
	}
	return s, ""
}
