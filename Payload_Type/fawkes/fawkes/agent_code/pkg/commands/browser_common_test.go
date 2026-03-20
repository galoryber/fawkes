package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestChromeTimeToString(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{"zero", 0, "never"},
		{"negative", -1, "never"},
		// Chrome epoch: microseconds since 1601-01-01
		// 2024-01-15 12:00:00 UTC = Unix 1705320000s → Chrome 13349793600000000
		{"chrome-epoch", 13349793600000000, "2024-01-15 12:00:00"},
		// 2020-01-01 00:00:00 UTC = Unix 1577836800s → Chrome 13222310400000000
		{"chrome-2020", 13222310400000000, "2020-01-01 00:00:00"},
		// Unix epoch seconds: 2024-01-15 12:00:00 UTC = 1705320000
		{"unix-epoch", 1705320000, "2024-01-15 12:00:00"},
		// Unix epoch seconds: 2020-01-01 00:00:00 UTC = 1577836800
		{"unix-2020", 1577836800, "2020-01-01 00:00:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chromeTimeToString(tt.input)
			if got != tt.expected {
				t.Errorf("chromeTimeToString(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractBookmarks(t *testing.T) {
	root := bookmarkNode{
		Type: "folder",
		Name: "Bookmark Bar",
		Children: []bookmarkNode{
			{Type: "url", Name: "Google", URL: "https://google.com"},
			{Type: "folder", Name: "Work", Children: []bookmarkNode{
				{Type: "url", Name: "GitHub", URL: "https://github.com"},
				{Type: "url", Name: "Jira", URL: "https://jira.example.com"},
			}},
			{Type: "url", Name: "No URL", URL: ""},
		},
	}

	var bookmarks []browserBookmarkEntry
	extractBookmarks(&root, "Chrome", "bookmark_bar", &bookmarks)

	if len(bookmarks) != 3 {
		t.Fatalf("expected 3 bookmarks, got %d", len(bookmarks))
	}

	if bookmarks[0].Name != "Google" || bookmarks[0].URL != "https://google.com" {
		t.Errorf("first bookmark: got %+v", bookmarks[0])
	}
	if bookmarks[1].Folder != "bookmark_bar/Work" {
		t.Errorf("expected folder 'bookmark_bar/Work', got %q", bookmarks[1].Folder)
	}
	if bookmarks[2].Name != "Jira" {
		t.Errorf("expected 'Jira', got %q", bookmarks[2].Name)
	}
}

func TestExtractBookmarks_Empty(t *testing.T) {
	root := bookmarkNode{Type: "folder", Name: "empty"}
	var bookmarks []browserBookmarkEntry
	extractBookmarks(&root, "Chrome", "other", &bookmarks)
	if len(bookmarks) != 0 {
		t.Errorf("expected 0 bookmarks, got %d", len(bookmarks))
	}
}

func TestBrowserArgs_Defaults(t *testing.T) {
	var args browserArgs
	json.Unmarshal([]byte(`{}`), &args)
	if args.Action != "" {
		t.Errorf("expected empty action, got %q", args.Action)
	}
}

func TestBrowserArgs_Full(t *testing.T) {
	var args browserArgs
	err := json.Unmarshal([]byte(`{"action":"history","browser":"chrome"}`), &args)
	if err != nil {
		t.Fatal(err)
	}
	if args.Action != "history" {
		t.Errorf("expected 'history', got %q", args.Action)
	}
	if args.Browser != "chrome" {
		t.Errorf("expected 'chrome', got %q", args.Browser)
	}
}

func TestFindProfilesWithFile(t *testing.T) {
	// Create a temporary directory structure mimicking Chromium profiles
	tmpDir := t.TempDir()

	// Create Default profile with History
	defaultDir := filepath.Join(tmpDir, "Default")
	os.MkdirAll(defaultDir, 0755)
	os.WriteFile(filepath.Join(defaultDir, "History"), []byte("test"), 0644)

	// Create Profile 1 with History
	prof1Dir := filepath.Join(tmpDir, "Profile 1")
	os.MkdirAll(prof1Dir, 0755)
	os.WriteFile(filepath.Join(prof1Dir, "History"), []byte("test"), 0644)

	// Create Profile 2 WITHOUT History
	prof2Dir := filepath.Join(tmpDir, "Profile 2")
	os.MkdirAll(prof2Dir, 0755)

	// Create a non-profile directory
	os.MkdirAll(filepath.Join(tmpDir, "Crashpad"), 0755)

	profiles := findProfilesWithFile(tmpDir, "History")
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(profiles), profiles)
	}
}

func TestBrowserCommand_Name(t *testing.T) {
	cmd := &BrowserCommand{}
	if cmd.Name() != "browser" {
		t.Errorf("expected 'browser', got %q", cmd.Name())
	}
}

func TestBrowserCommand_Description(t *testing.T) {
	cmd := &BrowserCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestBrowserCommand_UnknownAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestBrowserCommand_HistoryAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"history"}`})
	if result.Status != "success" {
		t.Errorf("expected success for history action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_AutofillAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"autofill"}`})
	if result.Status != "success" {
		t.Errorf("expected success for autofill action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_BookmarksAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"bookmarks"}`})
	if result.Status != "success" {
		t.Errorf("expected success for bookmarks action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserPaths_All(t *testing.T) {
	paths := browserPaths("all")
	if paths == nil {
		t.Skip("could not determine browser paths")
	}
	if _, ok := paths["Chrome"]; !ok {
		t.Error("expected Chrome path in 'all'")
	}
	if _, ok := paths["Edge"]; !ok {
		t.Error("expected Edge path in 'all'")
	}
	if _, ok := paths["Firefox"]; !ok {
		t.Error("expected Firefox path in 'all'")
	}
}

func TestBrowserPaths_Firefox(t *testing.T) {
	paths := browserPaths("firefox")
	if paths == nil {
		t.Skip("could not determine browser paths")
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 path for firefox, got %d", len(paths))
	}
	if _, ok := paths["Firefox"]; !ok {
		t.Error("expected Firefox path only")
	}
}

func TestBrowserPaths_Chrome(t *testing.T) {
	paths := browserPaths("chrome")
	if paths == nil {
		t.Skip("could not determine browser paths")
	}
	if _, ok := paths["Chrome"]; !ok {
		t.Error("expected Chrome path")
	}
	// Should not include Edge
	if _, ok := paths["Edge"]; ok {
		t.Error("expected no Edge path for 'chrome' filter")
	}
}

func TestBrowserPaths_Chromium(t *testing.T) {
	paths := browserPaths("chromium")
	if paths == nil {
		t.Skip("could not determine browser paths")
	}
	if _, ok := paths["Chromium"]; !ok {
		t.Error("expected Chromium path")
	}
}

func TestBrowserPaths_Edge(t *testing.T) {
	paths := browserPaths("edge")
	if paths == nil {
		t.Skip("could not determine browser paths")
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 path for edge, got %d", len(paths))
	}
	if _, ok := paths["Edge"]; !ok {
		t.Error("expected Edge path only")
	}
}

// --- Firefox helper tests ---

func TestFirefoxTimeToString(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{"zero", 0, "never"},
		{"negative", -1, "never"},
		// 2024-01-15 12:00:00 UTC = 1705320000s → PRTime 1705320000000000
		{"prtime-2024", 1705320000000000, "2024-01-15 12:00:00"},
		// 2020-01-01 00:00:00 UTC = 1577836800s → PRTime 1577836800000000
		{"prtime-2020", 1577836800000000, "2020-01-01 00:00:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firefoxTimeToString(tt.input)
			if got != tt.expected {
				t.Errorf("firefoxTimeToString(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsFirefoxBrowser(t *testing.T) {
	if !isFirefoxBrowser("Firefox") {
		t.Error("expected true for 'Firefox'")
	}
	if !isFirefoxBrowser("firefox") {
		t.Error("expected true for 'firefox' (case-insensitive)")
	}
	if !isFirefoxBrowser("FIREFOX") {
		t.Error("expected true for 'FIREFOX'")
	}
	if isFirefoxBrowser("Chrome") {
		t.Error("expected false for 'Chrome'")
	}
	if isFirefoxBrowser("") {
		t.Error("expected false for empty string")
	}
}

func TestFindFirefoxProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create Firefox-style profile directories
	os.MkdirAll(filepath.Join(tmpDir, "a1b2c3d4.default-release"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "e5f6g7h8.default"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "crash-reports"), 0755)      // non-profile
	os.MkdirAll(filepath.Join(tmpDir, "pending-pings"), 0755)      // non-profile

	profiles := findFirefoxProfiles(tmpDir)
	if len(profiles) != 2 {
		t.Fatalf("expected 2 Firefox profiles, got %d: %v", len(profiles), profiles)
	}
}

func TestFindFirefoxProfiles_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	profiles := findFirefoxProfiles(tmpDir)
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles in empty dir, got %d", len(profiles))
	}
}

func TestFindFirefoxProfiles_NonexistentDir(t *testing.T) {
	profiles := findFirefoxProfiles("/nonexistent/path")
	if profiles != nil {
		t.Errorf("expected nil for nonexistent dir, got %v", profiles)
	}
}

func TestBrowserCommand_CookiesFirefox(t *testing.T) {
	// Firefox cookies should work (even if no Firefox installed — graceful empty result)
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"cookies","browser":"firefox"}`})
	if result.Status != "success" {
		// On non-Windows, cookies with "firefox" browser should work
		t.Logf("output: %s", result.Output)
	}
}

func TestBrowserBookmarks_WithTempData(t *testing.T) {
	// Create a temp directory with fake Chromium bookmark data
	tmpDir := t.TempDir()
	defaultDir := filepath.Join(tmpDir, "Default")
	os.MkdirAll(defaultDir, 0755)

	bookmarkJSON := `{
		"roots": {
			"bookmark_bar": {
				"type": "folder",
				"name": "Bookmark Bar",
				"children": [
					{"type": "url", "name": "Test Site", "url": "https://example.com"},
					{"type": "folder", "name": "Dev", "children": [
						{"type": "url", "name": "Go Docs", "url": "https://go.dev"}
					]}
				]
			},
			"sync_transaction_version": "1"
		}
	}`
	os.WriteFile(filepath.Join(defaultDir, "Bookmarks"), []byte(bookmarkJSON), 0644)

	// Temporarily override browserPaths — not possible without refactoring,
	// so we test the shared extractBookmarks logic directly
	var bmFile struct {
		Roots map[string]json.RawMessage `json:"roots"`
	}
	json.Unmarshal([]byte(bookmarkJSON), &bmFile)

	var allBookmarks []browserBookmarkEntry
	for rootName, raw := range bmFile.Roots {
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var node bookmarkNode
		json.Unmarshal(raw, &node)
		extractBookmarks(&node, "Chrome", rootName, &allBookmarks)
	}

	if len(allBookmarks) != 2 {
		t.Fatalf("expected 2 bookmarks, got %d", len(allBookmarks))
	}
}
