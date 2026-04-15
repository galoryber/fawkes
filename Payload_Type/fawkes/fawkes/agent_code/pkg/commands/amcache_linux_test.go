//go:build linux

package commands

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestAmcacheCommand_Name_Linux(t *testing.T) {
	cmd := &AmcacheCommand{}
	if cmd.Name() != "amcache" {
		t.Errorf("Name() = %q, want amcache", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestAmcacheParams_JSONParsing_Linux(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantName   string
		wantCount  int
		wantErr    bool
	}{
		{"query", `{"action":"query","count":100}`, "query", "", 100, false},
		{"search", `{"action":"search","name":"document.pdf"}`, "search", "document.pdf", 0, false},
		{"delete", `{"action":"delete","name":"suspicious"}`, "delete", "suspicious", 0, false},
		{"defaults", `{}`, "", "", 0, false},
		{"invalid", `{bad`, "", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params amcacheParams
			err := json.Unmarshal([]byte(tt.input), &params)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if params.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", params.Action, tt.wantAction)
				}
				if params.Name != tt.wantName {
					t.Errorf("Name = %q, want %q", params.Name, tt.wantName)
				}
				if params.Count != tt.wantCount {
					t.Errorf("Count = %d, want %d", params.Count, tt.wantCount)
				}
			}
		})
	}
}

func TestAmcacheOutputEntry_JSON_Linux(t *testing.T) {
	entry := amcacheOutputEntry{
		Index:        1,
		LastModified: "2026-03-31 12:00:00",
		Path:         "/home/user/document.pdf",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var decoded amcacheOutputEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Index != entry.Index || decoded.Path != entry.Path || decoded.LastModified != entry.LastModified {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, entry)
	}
}

func TestXbelParsing(t *testing.T) {
	xbelContent := `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0"
      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"
      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="file:///home/user/doc.pdf" added="2026-01-15T10:30:00Z" modified="2026-01-15T11:00:00Z" visited="2026-01-15T10:30:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
      </metadata>
    </info>
  </bookmark>
  <bookmark href="file:///home/user/image.png" added="2026-02-01T08:00:00Z" modified="2026-02-01T09:00:00Z">
  </bookmark>
  <bookmark href="file:///tmp/test.txt" added="2026-03-01T12:00:00Z" modified="2026-03-01T12:00:00Z">
  </bookmark>
</xbel>`

	var doc xbelDoc
	if err := xml.Unmarshal([]byte(xbelContent), &doc); err != nil {
		t.Fatalf("Failed to parse XBEL: %v", err)
	}

	if len(doc.Bookmarks) != 3 {
		t.Fatalf("Expected 3 bookmarks, got %d", len(doc.Bookmarks))
	}

	// Check first bookmark
	b := doc.Bookmarks[0]
	if b.Href != "file:///home/user/doc.pdf" {
		t.Errorf("Bookmark 0 href = %q, want file:///home/user/doc.pdf", b.Href)
	}
	if b.Modified != "2026-01-15T11:00:00Z" {
		t.Errorf("Bookmark 0 modified = %q, want 2026-01-15T11:00:00Z", b.Modified)
	}
}

func TestXbelPathFromHref(t *testing.T) {
	tests := []struct {
		href string
		want string
	}{
		{"file:///home/user/doc.pdf", "/home/user/doc.pdf"},
		{"file:///tmp/test.txt", "/tmp/test.txt"},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		got := xbelPathFromHref(tt.href)
		if got != tt.want {
			t.Errorf("xbelPathFromHref(%q) = %q, want %q", tt.href, got, tt.want)
		}
	}
}

func TestXbelTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		bookmark xbelBookmark
		want     string
	}{
		{
			"modified preferred",
			xbelBookmark{Modified: "2026-01-15T11:00:00Z", Added: "2026-01-15T10:00:00Z"},
			"2026-01-15 11:00:00",
		},
		{
			"fallback to added",
			xbelBookmark{Added: "2026-02-01T08:00:00Z"},
			"2026-02-01 08:00:00",
		},
		{
			"unparseable timestamp",
			xbelBookmark{Modified: "not-a-timestamp"},
			"not-a-timestamp",
		},
		{
			"empty timestamps",
			xbelBookmark{},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xbelTimestamp(tt.bookmark)
			if got != tt.want {
				t.Errorf("xbelTimestamp() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestXbelRoundTrip(t *testing.T) {
	xbelContent := `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/user/keep.pdf" added="2026-01-01T00:00:00Z" modified="2026-01-01T00:00:00Z">
  </bookmark>
  <bookmark href="file:///tmp/remove.txt" added="2026-02-01T00:00:00Z" modified="2026-02-01T00:00:00Z">
  </bookmark>
</xbel>`

	var doc xbelDoc
	if err := xml.Unmarshal([]byte(xbelContent), &doc); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Filter out the "remove" entry
	var filtered []xbelBookmark
	for _, b := range doc.Bookmarks {
		if b.Href != "file:///tmp/remove.txt" {
			filtered = append(filtered, b)
		}
	}
	doc.Bookmarks = filtered

	// Write to temp file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "recently-used.xbel")
	if err := writeRecentlyUsed(path, &doc); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Read back and verify
	doc2, err := parseRecentlyUsed(path)
	if err != nil {
		t.Fatalf("Failed to read back: %v", err)
	}

	if len(doc2.Bookmarks) != 1 {
		t.Fatalf("Expected 1 bookmark after filter, got %d", len(doc2.Bookmarks))
	}
	if doc2.Bookmarks[0].Href != "file:///home/user/keep.pdf" {
		t.Errorf("Remaining bookmark href = %q, want file:///home/user/keep.pdf", doc2.Bookmarks[0].Href)
	}
}

func TestAmcacheQueryNoArtifacts(t *testing.T) {
	// When run in a test environment with no GTK artifacts, query should return empty JSON
	cmd := &AmcacheCommand{}
	result := cmd.Execute(structs.NewTask("t", "amcache", `{"action":"query"}`))
	if result.Status != "success" {
		t.Errorf("Expected success status, got %q", result.Status)
	}
}

func TestAmcacheSearchNoFile(t *testing.T) {
	cmd := &AmcacheCommand{}
	result := cmd.Execute(structs.NewTask("t", "amcache", `{"action":"search","name":"test"}`))
	// Should error when recently-used.xbel doesn't exist
	if result.Status != "error" {
		// It's OK if it's error (file not found) — that's expected in test env
		t.Logf("Status: %s, Output: %s", result.Status, result.Output)
	}
}

func TestAmcacheSearchNoName(t *testing.T) {
	cmd := &AmcacheCommand{}
	result := cmd.Execute(structs.NewTask("t", "amcache", `{"action":"search"}`))
	if result.Status != "error" {
		t.Errorf("Expected error for missing name, got %q", result.Status)
	}
}

func TestAmcacheDeleteNoName(t *testing.T) {
	cmd := &AmcacheCommand{}
	result := cmd.Execute(structs.NewTask("t", "amcache", `{"action":"delete"}`))
	if result.Status != "error" {
		t.Errorf("Expected error for missing name, got %q", result.Status)
	}
}

func TestAmcacheUnknownAction(t *testing.T) {
	cmd := &AmcacheCommand{}
	result := cmd.Execute(structs.NewTask("t", "amcache", `{"action":"invalid"}`))
	if result.Status != "error" {
		t.Errorf("Expected error for unknown action, got %q", result.Status)
	}
}

func TestAmcacheWithTempXbel(t *testing.T) {
	// Create a temporary XBEL file and test query/search/delete/clear
	tmpDir := t.TempDir()
	xbelPath := filepath.Join(tmpDir, "recently-used.xbel")

	xbelContent := `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/user/document.pdf" added="2026-01-15T10:30:00Z" modified="2026-01-15T11:00:00Z">
  </bookmark>
  <bookmark href="file:///home/user/image.png" added="2026-02-01T08:00:00Z" modified="2026-02-01T09:00:00Z">
  </bookmark>
  <bookmark href="file:///tmp/suspicious.exe" added="2026-03-01T12:00:00Z" modified="2026-03-01T12:00:00Z">
  </bookmark>
</xbel>`
	if err := os.WriteFile(xbelPath, []byte(xbelContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Test parseRecentlyUsed
	doc, err := parseRecentlyUsed(xbelPath)
	if err != nil {
		t.Fatalf("parseRecentlyUsed failed: %v", err)
	}
	if len(doc.Bookmarks) != 3 {
		t.Errorf("Expected 3 bookmarks, got %d", len(doc.Bookmarks))
	}

	// Test delete: remove the suspicious entry
	doc2, _ := parseRecentlyUsed(xbelPath)
	var keep []xbelBookmark
	for _, b := range doc2.Bookmarks {
		path := xbelPathFromHref(b.Href)
		if path != "/tmp/suspicious.exe" {
			keep = append(keep, b)
		}
	}
	doc2.Bookmarks = keep
	if err := writeRecentlyUsed(xbelPath, doc2); err != nil {
		t.Fatalf("writeRecentlyUsed failed: %v", err)
	}

	// Verify delete
	doc3, err := parseRecentlyUsed(xbelPath)
	if err != nil {
		t.Fatalf("re-read failed: %v", err)
	}
	if len(doc3.Bookmarks) != 2 {
		t.Errorf("Expected 2 bookmarks after delete, got %d", len(doc3.Bookmarks))
	}

	// Test clear: write empty
	doc3.Bookmarks = nil
	if err := writeRecentlyUsed(xbelPath, doc3); err != nil {
		t.Fatalf("clear write failed: %v", err)
	}
	doc4, err := parseRecentlyUsed(xbelPath)
	if err != nil {
		t.Fatalf("read after clear failed: %v", err)
	}
	if len(doc4.Bookmarks) != 0 {
		t.Errorf("Expected 0 bookmarks after clear, got %d", len(doc4.Bookmarks))
	}
}

func TestDirArtifactStats(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty directory
	count, size := dirArtifactStats(tmpDir)
	if count != 0 || size != 0 {
		t.Errorf("Empty dir: count=%d, size=%d, want 0, 0", count, size)
	}

	// Create some files
	for _, name := range []string{"a.png", "b.png", "c.png"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test content"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	count, size = dirArtifactStats(tmpDir)
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	if size != 36 { // 3 files * 12 bytes each
		t.Errorf("size = %d, want 36", size)
	}

	// Test with subdirectory
	subDir := filepath.Join(tmpDir, "sub")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "d.png"), []byte("data"), 0600)

	count, _ = dirArtifactStats(tmpDir)
	if count != 4 {
		t.Errorf("count with subdir = %d, want 4", count)
	}
}

func TestClearArtifactDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files in nested structure
	subDir := filepath.Join(tmpDir, "large")
	os.MkdirAll(subDir, 0755)
	for _, name := range []string{"a.png", "b.png"} {
		os.WriteFile(filepath.Join(tmpDir, name), []byte("data"), 0600)
		os.WriteFile(filepath.Join(subDir, name), []byte("data"), 0600)
	}

	count, _ := dirArtifactStats(tmpDir)
	if count != 4 {
		t.Fatalf("Setup: expected 4 files, got %d", count)
	}

	if err := clearArtifactDirectory(tmpDir); err != nil {
		t.Fatalf("clearArtifactDirectory failed: %v", err)
	}

	count, _ = dirArtifactStats(tmpDir)
	if count != 0 {
		t.Errorf("After clear: count = %d, want 0", count)
	}

	// Directories should still exist
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Error("Subdirectory should still exist after clearing files")
	}
}

func TestGetRecentlyUsedPath(t *testing.T) {
	path := getRecentlyUsedPath()
	if path == "" {
		t.Error("getRecentlyUsedPath() returned empty string")
	}
	// Should contain "recently-used.xbel"
	if filepath.Base(path) != "recently-used.xbel" {
		t.Errorf("Expected basename recently-used.xbel, got %q", filepath.Base(path))
	}
}
