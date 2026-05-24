package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

// TestFlexIntInvalidType covers the final error path (line 40) in
// flexInt.UnmarshalJSON — triggered when the JSON value is neither an integer
// nor a string (e.g., a boolean).
func TestFlexIntInvalidType(t *testing.T) {
	var v flexInt
	err := json.Unmarshal([]byte("true"), &v)
	if err == nil {
		t.Error("expected error for boolean input")
	}
}

// TestTriageScanDepthLimit covers the `depth > maxDepth && d.IsDir() →
// filepath.SkipDir` branch (line 155-156) in triageScan — triggered when a
// directory tree is deeper than maxDepth.
func TestTriageScanDepthLimit(t *testing.T) {
	dir := t.TempDir()

	// Create 4-level deep tree: dir/a/b/c/d/deep.pdf
	deep := filepath.Join(dir, "a", "b", "c", "d")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(dir, "a", "shallow.pdf"), []byte("shallow"), 0644)
	os.WriteFile(filepath.Join(deep, "deep.pdf"), []byte("deep"), 0644)

	task := structs.NewTask("t", "triage", "")
	args := triageArgs{MaxSize: 1024 * 1024, MaxFiles: 200}

	// Scan with maxDepth=1 — only dir/a level should be reached
	results := triageScan(task, []string{dir}, []string{".pdf"}, "doc", args, 1)

	for _, r := range results {
		if filepath.Base(r.Path) == "deep.pdf" {
			t.Error("deep.pdf should be excluded by depth limit")
		}
	}
}

// TestTriageScanPatternsDepthLimit covers the depth SkipDir branch (line 199-200)
// in triageScanPatterns.
func TestTriageScanPatternsDepthLimit(t *testing.T) {
	dir := t.TempDir()

	deep := filepath.Join(dir, "a", "b", "c")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(dir, "a", "id_rsa"), []byte("shallow_key"), 0644)
	os.WriteFile(filepath.Join(deep, "id_rsa"), []byte("deep_key"), 0644)

	task := structs.NewTask("t", "triage", "")
	args := triageArgs{MaxSize: 1024 * 1024, MaxFiles: 200}

	results := triageScanPatterns(task, []string{dir}, []string{"id_rsa"}, "cred", args, 1)

	for _, r := range results {
		if r.Path == filepath.Join(deep, "id_rsa") {
			t.Error("deep id_rsa should be excluded by depth limit")
		}
	}
}
