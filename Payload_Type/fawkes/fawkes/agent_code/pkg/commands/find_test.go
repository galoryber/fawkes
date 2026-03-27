package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestFindCommandName(t *testing.T) {
	cmd := &FindCommand{}
	if cmd.Name() != "find" {
		t.Errorf("expected 'find', got %q", cmd.Name())
	}
}

func TestFindMissingPattern(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"/tmp","pattern":""}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing pattern, got %q", result.Status)
	}
}

func TestFindSuccess(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "test.log"), []byte("y"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.txt"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "test.txt") {
		t.Error("output should contain test.txt")
	}
	if strings.Contains(result.Output, "test.log") {
		t.Error("output should not contain test.log")
	}
}

func TestFindNoMatches(t *testing.T) {
	tmp := t.TempDir()

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.xyz"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No files matching") {
		t.Error("should report no matches")
	}
}

func TestFindMaxDepth(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "a", "b", "c")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "shallow.txt"), []byte("y"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.txt","max_depth":1}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "shallow.txt") {
		t.Error("should find shallow.txt within depth 1")
	}
	if strings.Contains(result.Output, "deep.txt") {
		t.Error("should not find deep.txt beyond max_depth=1")
	}
}

func TestFindDefaultPath(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"pattern":"*.go"}`
	result := cmd.Execute(task)
	// Should succeed even without explicit path (defaults to ".")
	if result.Status != "success" {
		t.Errorf("expected success with default path, got %q", result.Status)
	}
}

func TestFindCancellation(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"/","pattern":"*","max_depth":1}`
	task.SetStop()
	result := cmd.Execute(task)
	// Should complete (possibly with partial results) without hanging
	if !result.Completed {
		t.Error("should complete even when cancelled")
	}
}

func TestFindPlainText(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = "*.go"
	result := cmd.Execute(task)
	// Plain text should be treated as pattern (not a parse error)
	if result.Status == "error" && strings.Contains(result.Output, "Error parsing") {
		t.Errorf("plain text should be treated as pattern, got parse error: %s", result.Output)
	}
}

func TestFindFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tc := range tests {
		result := formatFileSize(tc.bytes)
		if result != tc.expected {
			t.Errorf("formatFileSize(%d) = %q, want %q", tc.bytes, result, tc.expected)
		}
	}
}

// --- New tests for size, date, and type filtering ---

func TestFindMinSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "small.txt"), []byte("x"), 0644)      // 1 byte
	os.WriteFile(filepath.Join(tmp, "big.txt"), make([]byte, 1024), 0644) // 1 KB

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","min_size":512}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "small.txt") {
		t.Error("small.txt should be filtered out by min_size")
	}
	if !strings.Contains(result.Output, "big.txt") {
		t.Error("big.txt should match min_size filter")
	}
}

func TestFindMaxSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "small.txt"), []byte("x"), 0644)      // 1 byte
	os.WriteFile(filepath.Join(tmp, "big.txt"), make([]byte, 2048), 0644) // 2 KB

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","max_size":1024}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "small.txt") {
		t.Error("small.txt should match max_size filter")
	}
	if strings.Contains(result.Output, "big.txt") {
		t.Error("big.txt should be filtered out by max_size")
	}
}

func TestFindMinAndMaxSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "tiny.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "medium.txt"), make([]byte, 500), 0644)
	os.WriteFile(filepath.Join(tmp, "large.txt"), make([]byte, 2000), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","min_size":100,"max_size":1000}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "tiny.txt") {
		t.Error("tiny.txt should be filtered out")
	}
	if !strings.Contains(result.Output, "medium.txt") {
		t.Error("medium.txt should match size range")
	}
	if strings.Contains(result.Output, "large.txt") {
		t.Error("large.txt should be filtered out")
	}
}

func TestFindTypeFilesOnly(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*","type":"f"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "file.txt") {
		t.Error("should include files")
	}
	if strings.Contains(result.Output, "subdir") {
		t.Error("should exclude directories with type=f")
	}
}

func TestFindTypeDirsOnly(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*","type":"d"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "subdir") {
		t.Error("should include directories")
	}
	if strings.Contains(result.Output, "file.txt") {
		t.Error("should exclude files with type=d")
	}
}

func TestFindNewer(t *testing.T) {
	tmp := t.TempDir()
	// Create a file modified "now" (within last 5 minutes)
	os.WriteFile(filepath.Join(tmp, "new.txt"), []byte("x"), 0644)
	// Create a file and set its mtime to 2 hours ago
	oldFile := filepath.Join(tmp, "old.txt")
	os.WriteFile(oldFile, []byte("y"), 0644)
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldFile, twoHoursAgo, twoHoursAgo)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","newer":60}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "new.txt") {
		t.Error("new.txt should match newer=60 (modified within last 60 minutes)")
	}
	if strings.Contains(result.Output, "old.txt") {
		t.Error("old.txt should be filtered out by newer=60")
	}
}

func TestFindOlder(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "new.txt"), []byte("x"), 0644)
	oldFile := filepath.Join(tmp, "old.txt")
	os.WriteFile(oldFile, []byte("y"), 0644)
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldFile, twoHoursAgo, twoHoursAgo)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","older":60}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "new.txt") {
		t.Error("new.txt should be filtered out by older=60")
	}
	if !strings.Contains(result.Output, "old.txt") {
		t.Error("old.txt should match older=60 (modified more than 60 minutes ago)")
	}
}

func TestFindOutputIncludesTimestamp(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// Output should now include timestamp in YYYY-MM-DD HH:MM format
	year := time.Now().Format("2006")
	if !strings.Contains(result.Output, year) {
		t.Error("output should include modification timestamp")
	}
}

func TestFindDefaultPatternWithFilters(t *testing.T) {
	// When filters are set but no pattern, should default to "*"
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","type":"f"}`, tmp)
	result := cmd.Execute(task)
	if result.Status == "error" && strings.Contains(result.Output, "pattern is required") {
		t.Error("should not require pattern when filters are set")
	}
	if !strings.Contains(result.Output, "test.txt") {
		t.Error("should find files with default pattern")
	}
}

func TestFindFilterSummary(t *testing.T) {
	params := FindParams{
		MaxDepth: 5,
		MinSize:  1024,
		Type:     "f",
	}
	summary := findFilterSummary(params)
	if !strings.Contains(summary, "depth=5") {
		t.Error("should include depth in summary")
	}
	if !strings.Contains(summary, "min_size=1.0 KB") {
		t.Error("should include min_size in summary")
	}
	if !strings.Contains(summary, "type=f") {
		t.Error("should include type in summary")
	}
}

func TestFindFilterSummaryNoFilters(t *testing.T) {
	params := FindParams{MaxDepth: 10} // default depth
	summary := findFilterSummary(params)
	if summary != "" {
		t.Errorf("should return empty string when no filters active, got %q", summary)
	}
}

// --- Permission filter tests ---

func TestFindParsePerm_Empty(t *testing.T) {
	f := findParsePerm("")
	if f.set {
		t.Error("empty perm should not be set")
	}
}

func TestFindParsePerm_Suid(t *testing.T) {
	f := findParsePerm("suid")
	if !f.set {
		t.Fatal("suid should be set")
	}
	if f.specialBit != os.ModeSetuid {
		t.Errorf("specialBit = %v, want ModeSetuid", f.specialBit)
	}
}

func TestFindParsePerm_Sgid(t *testing.T) {
	f := findParsePerm("sgid")
	if !f.set || f.specialBit != os.ModeSetgid {
		t.Errorf("expected SGID filter, got set=%v specialBit=%v", f.set, f.specialBit)
	}
}

func TestFindParsePerm_Writable(t *testing.T) {
	f := findParsePerm("writable")
	if !f.set || f.permBits != 0002 {
		t.Errorf("expected writable filter (0002), got set=%v permBits=%04o", f.set, f.permBits)
	}
}

func TestFindParsePerm_Executable(t *testing.T) {
	f := findParsePerm("executable")
	if !f.set || f.permBits != 0111 {
		t.Errorf("expected executable filter (0111), got set=%v permBits=%04o", f.set, f.permBits)
	}
}

func TestFindParsePerm_OctalSuid(t *testing.T) {
	f := findParsePerm("4000")
	if !f.set {
		t.Fatal("4000 should be set")
	}
	if f.specialBit&os.ModeSetuid == 0 {
		t.Error("4000 should set SUID special bit")
	}
}

func TestFindParsePerm_OctalSgid(t *testing.T) {
	f := findParsePerm("2000")
	if !f.set {
		t.Fatal("2000 should be set")
	}
	if f.specialBit&os.ModeSetgid == 0 {
		t.Error("2000 should set SGID special bit")
	}
}

func TestFindParsePerm_OctalSuidSgid(t *testing.T) {
	f := findParsePerm("6755")
	if !f.set {
		t.Fatal("6755 should be set")
	}
	if f.specialBit&os.ModeSetuid == 0 {
		t.Error("6xxx should set SUID special bit")
	}
	if f.specialBit&os.ModeSetgid == 0 {
		t.Error("x2xx should set SGID special bit")
	}
}

func TestFindParsePerm_OctalWorldWritable(t *testing.T) {
	f := findParsePerm("0002")
	if !f.set {
		t.Fatal("0002 should be set")
	}
	if f.permBits&0002 == 0 {
		t.Error("0002 should set world-writable bit")
	}
}

func TestFindParsePerm_Invalid(t *testing.T) {
	f := findParsePerm("invalid")
	if f.set {
		t.Error("invalid perm should not be set")
	}
}

func TestFindParsePerm_CaseInsensitive(t *testing.T) {
	f := findParsePerm("SUID")
	if !f.set {
		t.Error("SUID (uppercase) should be recognized")
	}
}

func TestFindMatchPerm_Executable(t *testing.T) {
	f := findParsePerm("executable")
	if !findMatchPerm(0755, f) {
		t.Error("0755 should match executable filter")
	}
	if findMatchPerm(0644, f) {
		t.Error("0644 should not match executable filter")
	}
}

func TestFindMatchPerm_WorldWritable(t *testing.T) {
	f := findParsePerm("writable")
	if !findMatchPerm(0666, f) {
		t.Error("0666 should match writable filter")
	}
	if findMatchPerm(0644, f) {
		t.Error("0644 should not match writable filter")
	}
	if !findMatchPerm(0777, f) {
		t.Error("0777 should match writable filter")
	}
}

func TestFindMatchPerm_Suid(t *testing.T) {
	f := findParsePerm("suid")
	if !findMatchPerm(os.ModeSetuid|0755, f) {
		t.Error("SUID|0755 should match suid filter")
	}
	if findMatchPerm(0755, f) {
		t.Error("plain 0755 should not match suid filter")
	}
}

func TestFindMatchPerm_NoFilter(t *testing.T) {
	f := findPermFilter{} // not set
	if !findMatchPerm(0644, f) {
		t.Error("no filter should match everything")
	}
}

// --- Owner filter tests ---

func TestFindResolveOwner_NumericUID(t *testing.T) {
	uid := findResolveOwner("0")
	if uid != 0 {
		t.Errorf("expected 0 for root UID, got %d", uid)
	}
}

func TestFindResolveOwner_Username(t *testing.T) {
	uid := findResolveOwner("root")
	if uid != 0 {
		t.Errorf("expected 0 for root username, got %d", uid)
	}
}

func TestFindResolveOwner_Invalid(t *testing.T) {
	uid := findResolveOwner("nonexistent_user_xyz_12345")
	if uid != -1 {
		t.Errorf("expected -1 for nonexistent user, got %d", uid)
	}
}

func TestFindResolveOwner_LargeUID(t *testing.T) {
	uid := findResolveOwner("65534")
	if uid != 65534 {
		t.Errorf("expected 65534 for nobody UID, got %d", uid)
	}
}

// --- Integration tests with perm and owner filters ---

func TestFindWithPermExecutable(t *testing.T) {
	tmp := t.TempDir()
	execFile := filepath.Join(tmp, "run.sh")
	os.WriteFile(execFile, []byte("#!/bin/sh"), 0755)
	noExecFile := filepath.Join(tmp, "data.txt")
	os.WriteFile(noExecFile, []byte("data"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","perm":"executable"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "run.sh") {
		t.Error("executable file should be found")
	}
	if strings.Contains(result.Output, "data.txt") {
		t.Error("non-executable file should be filtered out")
	}
}

func TestFindWithPermWritable(t *testing.T) {
	tmp := t.TempDir()
	writableFile := filepath.Join(tmp, "public.txt")
	os.WriteFile(writableFile, []byte("open"), 0644)
	os.Chmod(writableFile, 0666) // explicitly set after creation to bypass umask
	privateFile := filepath.Join(tmp, "private.txt")
	os.WriteFile(privateFile, []byte("closed"), 0600)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","perm":"writable"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "public.txt") {
		t.Error("world-writable file should be found")
	}
	if strings.Contains(result.Output, "private.txt") {
		t.Error("non-world-writable file should be filtered out")
	}
}

func TestFindWithOwnerFilter(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "myfile.txt"), []byte("x"), 0644)

	// Filter for current user — should find the file
	currentUID := fmt.Sprintf("%d", os.Getuid())
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","owner":"%s"}`, tmp, currentUID)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "myfile.txt") {
		t.Error("file owned by current user should be found")
	}

	// Filter for root — should NOT find the file (unless running as root)
	if os.Getuid() != 0 {
		task2 := structs.NewTask("t", "find", "")
		task2.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","owner":"root"}`, tmp)
		result2 := cmd.Execute(task2)
		if strings.Contains(result2.Output, "myfile.txt") {
			t.Error("file not owned by root should be filtered out")
		}
	}
}

func TestFindDefaultPatternWithPermFilter(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.sh"), []byte("#!/bin/sh"), 0755)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","perm":"executable"}`, tmp)
	result := cmd.Execute(task)
	if result.Status == "error" && strings.Contains(result.Output, "pattern is required") {
		t.Error("perm filter alone should not require explicit pattern")
	}
}

func TestFindFilterSummaryWithPerm(t *testing.T) {
	params := FindParams{MaxDepth: 10, Perm: "suid"}
	summary := findFilterSummary(params)
	if !strings.Contains(summary, "perm=suid") {
		t.Errorf("summary should include perm, got %q", summary)
	}
}

func TestFindFilterSummaryWithOwner(t *testing.T) {
	params := FindParams{MaxDepth: 10, Owner: "root"}
	summary := findFilterSummary(params)
	if !strings.Contains(summary, "owner=root") {
		t.Errorf("summary should include owner, got %q", summary)
	}
}
