package commands

import (
	"strings"

	"fawkes/pkg/structs"
)

// parseDomainUser extracts domain and username from composite credential strings.
// Supports "DOMAIN\user" and "user@domain" formats.
// Returns (domain, user). If no separator found, returns ("", original).
func parseDomainUser(input string) (domain, user string) {
	if parts := strings.SplitN(input, `\`, 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	if parts := strings.SplitN(input, "@", 2); len(parts) == 2 {
		return parts[1], parts[0]
	}
	return "", input
}

// stripLMPrefix removes the LM hash prefix from an "LM:NT" format hash string.
// If the input doesn't match "LM:NT" format (two 32-char hex parts), returns it as-is.
func stripLMPrefix(hash string) string {
	hash = strings.TrimSpace(hash)
	if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
		return parts[1]
	}
	return hash
}

// zeroCredentials zeroes multiple credential string fields.
// Use with defer: defer zeroCredentials(&args.Password, &args.Hash)
func zeroCredentials(fields ...*string) {
	for _, f := range fields {
		structs.ZeroString(f)
	}
}
