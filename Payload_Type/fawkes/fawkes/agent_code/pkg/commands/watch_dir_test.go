package commands

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestWatchDirName(t *testing.T) {
	cmd := &WatchDirCommand{}
	if cmd.Name() != "watch-dir" {
		t.Errorf("expected 'watch-dir', got %q", cmd.Name())
	}
}

func TestWatchDirDescription(t *testing.T) {
	cmd := &WatchDirCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestWatchDirMissingPath(t *testing.T) {
	cmd := &WatchDirCommand{}
	params, _ := json.Marshal(watchDirParams{})
	task := structs.NewTask("test-1", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "path") {
		t.Errorf("expected path error, got: %s", result.Output)
	}
}

func TestWatchDirNonexistentPath(t *testing.T) {
	cmd := &WatchDirCommand{}
	params, _ := json.Marshal(watchDirParams{Path: "/nonexistent/path/abc123"})
	task := structs.NewTask("test-2", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "Error accessing") {
		t.Errorf("expected access error, got: %s", result.Output)
	}
}

func TestWatchDirNotADirectory(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpFile, err := os.CreateTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	params, _ := json.Marshal(watchDirParams{Path: tmpFile.Name()})
	task := structs.NewTask("test-3", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "not a directory") {
		t.Errorf("expected directory error, got: %s", result.Output)
	}
}

func TestWatchDirInvalidJSON(t *testing.T) {
	cmd := &WatchDirCommand{}
	task := structs.NewTask("test-4", "watch-dir", "not json")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got: %s", result.Status)
	}
}

func TestWatchDirNoChanges(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file that exists before monitoring starts
	os.WriteFile(filepath.Join(tmpDir, "existing.txt"), []byte("hello"), 0644)

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 2,
	})
	task := structs.NewTask("test-5", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected completed, got: %s", result.Status)
	}
	if !strings.Contains(result.Output, "No changes detected") {
		t.Errorf("expected no changes, got: %s", result.Output)
	}
}

func TestWatchDirDetectsNewFile(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Start watching with short interval; create a file after a brief delay
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.WriteFile(filepath.Join(tmpDir, "new_file.txt"), []byte("new content"), 0644)
	}()

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 4,
	})
	task := structs.NewTask("test-6", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected completed, got: %s", result.Status)
	}
	if !strings.Contains(result.Output, "CREATED") {
		t.Errorf("expected CREATED event, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "new_file.txt") {
		t.Errorf("expected new_file.txt in output, got: %s", result.Output)
	}
}

func TestWatchDirDetectsDeletedFile(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file before monitoring
	filePath := filepath.Join(tmpDir, "to_delete.txt")
	os.WriteFile(filePath, []byte("delete me"), 0644)

	// Delete after monitoring starts
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.Remove(filePath)
	}()

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 4,
	})
	task := structs.NewTask("test-7", "watch-dir", string(params))
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "DELETED") {
		t.Errorf("expected DELETED event, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "to_delete.txt") {
		t.Errorf("expected to_delete.txt in output, got: %s", result.Output)
	}
}

func TestWatchDirDetectsModifiedFile(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file before monitoring
	filePath := filepath.Join(tmpDir, "modify_me.txt")
	os.WriteFile(filePath, []byte("original"), 0644)

	// Modify after monitoring starts (change size to ensure detection)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.WriteFile(filePath, []byte("modified content is longer"), 0644)
	}()

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 4,
	})
	task := structs.NewTask("test-8", "watch-dir", string(params))
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "MODIFIED") {
		t.Errorf("expected MODIFIED event, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "modify_me.txt") {
		t.Errorf("expected modify_me.txt in output, got: %s", result.Output)
	}
}

func TestWatchDirPatternFilter(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create files after monitoring starts
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.WriteFile(filepath.Join(tmpDir, "match.docx"), []byte("doc"), 0644)
		os.WriteFile(filepath.Join(tmpDir, "ignore.txt"), []byte("txt"), 0644)
	}()

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 4,
		Pattern:  "*.docx",
	})
	task := structs.NewTask("test-9", "watch-dir", string(params))
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "match.docx") {
		t.Errorf("expected match.docx in output, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "ignore.txt") {
		t.Errorf("ignore.txt should not appear (filtered out), got: %s", result.Output)
	}
}

func TestWatchDirHashDetection(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create file before monitoring
	filePath := filepath.Join(tmpDir, "hash_test.txt")
	os.WriteFile(filePath, []byte("original"), 0644)

	// Overwrite with same-size but different content after monitoring starts
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.WriteFile(filePath, []byte("modified"), 0644) // same length as "original"
	}()

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 4,
		Hash:     true,
	})
	task := structs.NewTask("test-10", "watch-dir", string(params))
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "MODIFIED") {
		t.Errorf("expected MODIFIED with hash detection, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "content changed") {
		t.Errorf("expected 'content changed' detail, got: %s", result.Output)
	}
}

func TestWatchDirTaskCancellation(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Interval: 1,
		Duration: 0, // No duration limit — should stop via cancellation
	})
	task := structs.NewTask("test-11", "watch-dir", string(params))

	// Cancel the task after a brief delay
	go func() {
		time.Sleep(2 * time.Second)
		task.SetStop()
	}()

	start := time.Now()
	result := cmd.Execute(task)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("task should have been cancelled quickly, took %s", elapsed)
	}
	if result.Status != "success" {
		t.Errorf("expected completed after cancellation, got: %s", result.Status)
	}
}

func TestWatchDirDepthLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create nested structure
	deep := filepath.Join(tmpDir, "a", "b", "c", "d")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(tmpDir, "a", "level1.txt"), []byte("1"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "a", "b", "level2.txt"), []byte("2"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "a", "b", "c", "level3.txt"), []byte("3"), 0644)
	os.WriteFile(filepath.Join(deep, "level4.txt"), []byte("4"), 0644)

	// Scan with depth 2
	result := scanDirectory(tmpDir, 2, "", false)

	if _, ok := result[filepath.Join("a", "level1.txt")]; !ok {
		t.Error("level1.txt should be in scan (depth 1)")
	}
	if _, ok := result[filepath.Join("a", "b", "level2.txt")]; !ok {
		t.Error("level2.txt should be in scan (depth 2)")
	}
	if _, ok := result[filepath.Join("a", "b", "c", "level3.txt")]; ok {
		t.Error("level3.txt should NOT be in scan (depth 3, limit is 2)")
	}
}

func TestScanDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.log"), []byte("world"), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "subdir", "nested.txt"), []byte("nested"), 0644)

	result := scanDirectory(tmpDir, 3, "", false)

	if len(result) != 3 {
		t.Errorf("expected 3 files, got %d", len(result))
	}
	if snap, ok := result["file1.txt"]; !ok {
		t.Error("file1.txt missing from scan")
	} else if snap.Size != 5 {
		t.Errorf("file1.txt size should be 5, got %d", snap.Size)
	}
}

func TestScanDirectoryWithPattern(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	os.WriteFile(filepath.Join(tmpDir, "match.txt"), []byte("yes"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "skip.log"), []byte("no"), 0644)

	result := scanDirectory(tmpDir, 3, "*.txt", false)
	if len(result) != 1 {
		t.Errorf("expected 1 file with pattern *.txt, got %d", len(result))
	}
	if _, ok := result["match.txt"]; !ok {
		t.Error("match.txt should be in scan results")
	}
}

func TestScanDirectoryWithHash(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := []byte("hash me")
	os.WriteFile(filepath.Join(tmpDir, "hashfile.txt"), content, 0644)

	result := scanDirectory(tmpDir, 3, "", true)
	snap, ok := result["hashfile.txt"]
	if !ok {
		t.Fatal("hashfile.txt missing from scan")
	}
	if snap.Hash == "" {
		t.Error("hash should not be empty when hash=true")
	}

	expected := fmt.Sprintf("%x", md5.Sum(content))
	if snap.Hash != expected {
		t.Errorf("hash mismatch: got %s, want %s", snap.Hash, expected)
	}
}

func TestCompareSnapshotsNoChanges(t *testing.T) {
	baseline := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: time.Now()},
	}
	current := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: baseline["file.txt"].ModTime},
	}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 0 {
		t.Errorf("expected no events, got %d", len(events))
	}
}

func TestCompareSnapshotsCreated(t *testing.T) {
	baseline := map[string]fileSnapshot{}
	current := map[string]fileSnapshot{
		"new.txt": {Size: 50, ModTime: time.Now()},
	}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "CREATED" {
		t.Errorf("expected CREATED, got %s", events[0].Action)
	}
	if events[0].Path != "new.txt" {
		t.Errorf("expected new.txt, got %s", events[0].Path)
	}
}

func TestCompareSnapshotsDeleted(t *testing.T) {
	baseline := map[string]fileSnapshot{
		"gone.txt": {Size: 100, ModTime: time.Now()},
	}
	current := map[string]fileSnapshot{}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "DELETED" {
		t.Errorf("expected DELETED, got %s", events[0].Action)
	}
}

func TestCompareSnapshotsModifiedSize(t *testing.T) {
	now := time.Now()
	baseline := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: now},
	}
	current := map[string]fileSnapshot{
		"file.txt": {Size: 200, ModTime: now},
	}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "MODIFIED" {
		t.Errorf("expected MODIFIED, got %s", events[0].Action)
	}
	if !strings.Contains(events[0].Detail, "size") {
		t.Errorf("expected size detail, got %s", events[0].Detail)
	}
}

func TestCompareSnapshotsModifiedMtime(t *testing.T) {
	baseline := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: time.Now().Add(-time.Hour)},
	}
	current := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: time.Now()},
	}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "MODIFIED" {
		t.Errorf("expected MODIFIED, got %s", events[0].Action)
	}
	if !strings.Contains(events[0].Detail, "mtime") {
		t.Errorf("expected mtime detail, got %s", events[0].Detail)
	}
}

func TestCompareSnapshotsModifiedHash(t *testing.T) {
	now := time.Now()
	baseline := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: now, Hash: "abc123"},
	}
	current := map[string]fileSnapshot{
		"file.txt": {Size: 100, ModTime: now, Hash: "def456"},
	}

	events := compareSnapshots(baseline, current, true)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "MODIFIED" {
		t.Errorf("expected MODIFIED, got %s", events[0].Action)
	}
	if !strings.Contains(events[0].Detail, "content changed") {
		t.Errorf("expected 'content changed' detail, got %s", events[0].Detail)
	}
}

func TestCompareSnapshotsMultipleEvents(t *testing.T) {
	now := time.Now()
	baseline := map[string]fileSnapshot{
		"keep.txt":   {Size: 100, ModTime: now},
		"delete.txt": {Size: 50, ModTime: now},
		"modify.txt": {Size: 75, ModTime: now},
	}
	current := map[string]fileSnapshot{
		"keep.txt":   {Size: 100, ModTime: now},
		"modify.txt": {Size: 150, ModTime: now},
		"new.txt":    {Size: 25, ModTime: now},
	}

	events := compareSnapshots(baseline, current, false)
	if len(events) != 3 {
		t.Fatalf("expected 3 events (created+modified+deleted), got %d", len(events))
	}

	actions := make(map[string]bool)
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions["CREATED"] || !actions["MODIFIED"] || !actions["DELETED"] {
		t.Errorf("expected CREATED, MODIFIED, DELETED events, got: %v", actions)
	}
}

func TestHashFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "hash-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := []byte("test content for hashing")
	tmpFile.Write(content)
	tmpFile.Close()

	hash := watchDirHashFile(tmpFile.Name())
	expected := fmt.Sprintf("%x", md5.Sum(content))
	if hash != expected {
		t.Errorf("hash mismatch: got %s, want %s", hash, expected)
	}
}

func TestHashFileNonexistent(t *testing.T) {
	hash := watchDirHashFile("/nonexistent/file/abc123")
	if hash != "" {
		t.Errorf("expected empty hash for nonexistent file, got %s", hash)
	}
}

func TestWatchDirFormatResult(t *testing.T) {
	events := []watchEvent{
		{Time: time.Now(), Action: "CREATED", Path: "new.txt", Detail: "size: 100"},
		{Time: time.Now(), Action: "DELETED", Path: "old.txt", Detail: ""},
	}
	params := watchDirParams{Path: "/tmp/test", Interval: 5, Depth: 3}
	result := watchDirFormatResult("/tmp/test", events, time.Now().Add(-10*time.Second), params)

	if result.Status != "success" {
		t.Errorf("expected completed, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "2 total") {
		t.Errorf("expected '2 total' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 created") {
		t.Errorf("expected '1 created' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 deleted") {
		t.Errorf("expected '1 deleted' in output, got: %s", result.Output)
	}
}

func TestWatchDirFormatResultNoChanges(t *testing.T) {
	params := watchDirParams{Path: "/tmp/test", Interval: 5, Depth: 3, Hash: true}
	result := watchDirFormatResult("/tmp/test", nil, time.Now(), params)

	if !strings.Contains(result.Output, "No changes detected") {
		t.Errorf("expected 'No changes detected', got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "MD5 hashing: enabled") {
		t.Errorf("expected hash info in output, got: %s", result.Output)
	}
}

func TestWatchDirDefaultParams(t *testing.T) {
	cmd := &WatchDirCommand{}
	tmpDir, err := os.MkdirTemp("", "watch-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Only set path and duration, let defaults kick in
	params, _ := json.Marshal(watchDirParams{
		Path:     tmpDir,
		Duration: 2,
	})
	task := structs.NewTask("test-defaults", "watch-dir", string(params))
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected completed, got: %s", result.Status)
	}
	// Defaults: interval=5, depth=3
	if !strings.Contains(result.Output, "Interval: 5s") {
		t.Errorf("expected default interval 5s in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Depth: 3") {
		t.Errorf("expected default depth 3 in output, got: %s", result.Output)
	}
}
