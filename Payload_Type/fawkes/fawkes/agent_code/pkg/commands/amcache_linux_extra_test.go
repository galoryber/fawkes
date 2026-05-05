//go:build linux

package commands

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testXBEL = `<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/user/secret.pdf" added="2026-01-15T10:30:00Z" modified="2026-01-15T11:00:00Z"></bookmark>
  <bookmark href="file:///home/user/image.png" added="2026-02-01T08:00:00Z" modified="2026-02-01T09:00:00Z"></bookmark>
</xbel>`

// makeXBELHome creates a temp dir with a valid recently-used.xbel at the XDG location.
// Returns the temp dir path. The caller must set HOME via t.Setenv before calling functions
// that rely on getRecentlyUsedPath().
func makeXBELHome(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	xdgDir := filepath.Join(dir, ".local", "share")
	if err := os.MkdirAll(xdgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdgDir, "recently-used.xbel"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestGetRecentlyUsedPathXDGExists covers the "XDG path exists → return xdgPath"
// branch in getRecentlyUsedPath (line 92).
func TestGetRecentlyUsedPathXDGExists(t *testing.T) {
	home := makeXBELHome(t, testXBEL)
	t.Setenv("HOME", home)

	path := getRecentlyUsedPath()
	want := filepath.Join(home, ".local", "share", "recently-used.xbel")
	if path != want {
		t.Errorf("expected %q, got %q", want, path)
	}
}

// TestGetArtifactPathsNoHome covers the home=="" early return in getArtifactPaths (line 105-107).
func TestGetArtifactPathsNoHome(t *testing.T) {
	t.Setenv("HOME", "")
	thumbs, tracker := getArtifactPaths()
	if thumbs != "" || tracker != "" {
		t.Errorf("expected empty paths for empty HOME, got %q, %q", thumbs, tracker)
	}
}

// TestGetArtifactPathsTracker3 covers the "tracker3 exists → return tracker3" branch
// in getArtifactPaths (line 111-113).
func TestGetArtifactPathsTracker3(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tracker3 := filepath.Join(home, ".cache", "tracker3")
	if err := os.MkdirAll(tracker3, 0755); err != nil {
		t.Fatal(err)
	}

	_, trackerPath := getArtifactPaths()
	if trackerPath != tracker3 {
		t.Errorf("expected tracker3 path %q, got %q", tracker3, trackerPath)
	}
}

// TestParseRecentlyUsedInvalidXML covers the xml.Unmarshal error path in
// parseRecentlyUsed (line 128).
func TestParseRecentlyUsedInvalidXML(t *testing.T) {
	f, err := os.CreateTemp("", "xbel_bad_*.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("<not valid xml <<>>")
	f.Close()

	_, err = parseRecentlyUsed(f.Name())
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

// TestWriteRecentlyUsedEmptyVersion covers the doc.Version=="" branch in
// writeRecentlyUsed (line 341-343) that defaults the version to "1.0".
func TestWriteRecentlyUsedEmptyVersion(t *testing.T) {
	f, err := os.CreateTemp("", "xbel_write_*.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	doc := &xbelDoc{
		// Version intentionally left empty — should be set to "1.0" by writeRecentlyUsed
		Bookmarks: []xbelBookmark{
			{Href: "file:///tmp/test.txt"},
		},
	}
	if err := writeRecentlyUsed(f.Name(), doc); err != nil {
		t.Fatalf("writeRecentlyUsed failed: %v", err)
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	var out xbelDoc
	if err := xml.Unmarshal(data, &out); err != nil {
		t.Fatalf("failed to parse written XBEL: %v", err)
	}
	if out.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", out.Version)
	}
}

// TestAmcacheDeleteWithRealFile covers the main body of amcacheDelete (lines 265-288)
// by pointing HOME at a temp dir containing a valid recently-used.xbel.
func TestAmcacheDeleteWithRealFile(t *testing.T) {
	home := makeXBELHome(t, testXBEL)
	t.Setenv("HOME", home)

	// Delete entry matching "secret"
	result := amcacheDelete(amcacheParams{Name: "secret"})
	if result.Status != "success" {
		t.Fatalf("amcacheDelete failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Removed 1") {
		t.Errorf("expected 'Removed 1', got: %s", result.Output)
	}

	// Verify: re-parse and check only image.png remains
	xbelPath := filepath.Join(home, ".local", "share", "recently-used.xbel")
	doc, err := parseRecentlyUsed(xbelPath)
	if err != nil {
		t.Fatalf("re-read failed: %v", err)
	}
	if len(doc.Bookmarks) != 1 {
		t.Errorf("expected 1 bookmark remaining, got %d", len(doc.Bookmarks))
	}
}

// TestAmcacheDeleteNoMatch covers the "removed == 0" branch in amcacheDelete (line 278-280).
func TestAmcacheDeleteNoMatch(t *testing.T) {
	home := makeXBELHome(t, testXBEL)
	t.Setenv("HOME", home)

	result := amcacheDelete(amcacheParams{Name: "nonexistent_entry_xyz"})
	if result.Status != "success" {
		t.Fatalf("expected success for no-match, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "No entries matching") {
		t.Errorf("expected 'No entries matching', got: %s", result.Output)
	}
}

// TestAmcacheClearWithRealFile covers amcacheClear (line 291+) by pointing HOME
// at a temp dir with a valid recently-used.xbel.
func TestAmcacheClearWithRealFile(t *testing.T) {
	home := makeXBELHome(t, testXBEL)
	t.Setenv("HOME", home)

	result := amcacheClear()
	if result.Status != "success" {
		t.Fatalf("amcacheClear failed: %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Cleared") {
		t.Errorf("expected 'Cleared' in output, got: %s", result.Output)
	}

	// Verify XBEL is now empty
	xbelPath := filepath.Join(home, ".local", "share", "recently-used.xbel")
	doc, err := parseRecentlyUsed(xbelPath)
	if err != nil {
		t.Fatalf("re-read failed: %v", err)
	}
	if len(doc.Bookmarks) != 0 {
		t.Errorf("expected 0 bookmarks after clear, got %d", len(doc.Bookmarks))
	}
}

// TestAmcacheClearNoArtifacts covers the totalCleared==0 branch (line 331-333)
// in amcacheClear when there is no recently-used.xbel file.
func TestAmcacheClearNoArtifacts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// No XBEL file created — amcacheClear should report nothing to clear

	result := amcacheClear()
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "No forensic artifacts") {
		t.Errorf("expected 'No forensic artifacts' message, got: %s", result.Output)
	}
}
