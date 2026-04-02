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

// browserDownloads extracts download history from Chromium-based browsers and Firefox.
// Chromium: reads the downloads table from History SQLite database.
// Firefox: reads downloads.json from each profile directory.
// No decryption needed — works on all platforms.
func browserDownloads(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine browser data paths")
	}

	type downloadEntry struct {
		Browser   string
		URL       string
		FilePath  string
		Size      int64
		State     string
		MimeType  string
		StartTime string
	}

	var allEntries []downloadEntry
	var errors []string

	for browserName, userDataDir := range paths {
		if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
			continue
		}

		if isFirefoxBrowser(browserName) {
			// Firefox: parse downloads.json from each profile
			profiles := findFirefoxProfiles(userDataDir)
			for _, profileDir := range profiles {
				dlPath := filepath.Join(profileDir, "downloads.json")
				profileName := filepath.Base(profileDir)

				data, err := os.ReadFile(dlPath)
				if err != nil {
					// downloads.json may not exist if no downloads have occurred
					continue
				}
				defer structs.ZeroBytes(data)

				var dlFile struct {
					List []struct {
						Source      string `json:"source"`
						Target      string `json:"target"`
						StartTime   int64  `json:"startTime"` // milliseconds since epoch
						TotalBytes  int64  `json:"totalBytes"`
						State       int    `json:"state"` // 0=downloading, 1=succeeded, 2=failed, 3=canceled, 4=paused, 5=blocked
						ContentType string `json:"contentType"`
					} `json:"list"`
				}
				if err := json.Unmarshal(data, &dlFile); err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): parse downloads.json: %v", browserName, profileName, err))
					continue
				}

				label := browserName
				if profileName != "Default" {
					label = fmt.Sprintf("%s (%s)", browserName, profileName)
				}

				for _, dl := range dlFile.List {
					// Convert file:// URI to path
					filePath := dl.Target
					if strings.HasPrefix(filePath, "file:///") {
						filePath = filePath[len("file://"):]
					} else if strings.HasPrefix(filePath, "file://") {
						filePath = filePath[len("file://"):]
					}

					state := firefoxDownloadState(dl.State)
					startTime := "unknown"
					if dl.StartTime > 0 {
						// StartTime is milliseconds since epoch
						t := time.Unix(dl.StartTime/1000, (dl.StartTime%1000)*1000000)
						startTime = t.UTC().Format("2006-01-02 15:04:05")
					}

					allEntries = append(allEntries, downloadEntry{
						Browser:   label,
						URL:       dl.Source,
						FilePath:  filePath,
						Size:      dl.TotalBytes,
						State:     state,
						MimeType:  dl.ContentType,
						StartTime: startTime,
					})
				}
			}
			continue
		}

		// Chromium-based: downloads table in History database
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

			rows, err := db.Query("SELECT target_path, tab_url, total_bytes, start_time, state, mime_type FROM downloads ORDER BY start_time DESC LIMIT 500")
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
				var targetPath, tabURL, mimeType string
				var totalBytes, startTime int64
				var state int

				if err := rows.Scan(&targetPath, &tabURL, &totalBytes, &startTime, &state, &mimeType); err != nil {
					continue
				}

				allEntries = append(allEntries, downloadEntry{
					Browser:   label,
					URL:       tabURL,
					FilePath:  targetPath,
					Size:      totalBytes,
					State:     chromeDownloadState(state),
					MimeType:  mimeType,
					StartTime: chromeTimeToString(startTime),
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
	sb.WriteString(fmt.Sprintf("=== Browser Downloads (%d entries) ===\n\n", len(allEntries)))

	for _, e := range allEntries {
		sizeStr := "unknown"
		if e.Size >= 0 {
			sizeStr = formatBytes(uint64(e.Size))
		}
		sb.WriteString(fmt.Sprintf("[%s] %s (%s, %s)\n  URL: %s\n  File: %s\n",
			e.Browser, e.State, sizeStr, e.StartTime,
			truncStr(e.URL, 120), truncStr(e.FilePath, 120)))
		if e.MimeType != "" {
			sb.WriteString(fmt.Sprintf("  Type: %s\n", e.MimeType))
		}
		sb.WriteString("\n")
	}

	if len(errors) > 0 {
		sb.WriteString("--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	if len(allEntries) == 0 && len(errors) == 0 {
		sb.WriteString("No download history found.\n")
	}

	return successResult(sb.String())
}

// chromeDownloadState converts a Chrome download state int to a human-readable string.
func chromeDownloadState(state int) string {
	switch state {
	case 0:
		return "In Progress"
	case 1:
		return "Complete"
	case 2:
		return "Cancelled"
	case 3:
		return "Interrupted"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// firefoxDownloadState converts a Firefox download state int to a human-readable string.
func firefoxDownloadState(state int) string {
	switch state {
	case 0:
		return "Downloading"
	case 1:
		return "Complete"
	case 2:
		return "Failed"
	case 3:
		return "Cancelled"
	case 4:
		return "Paused"
	case 5:
		return "Blocked"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

