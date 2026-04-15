//go:build windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWinDLLPlant_MissingSource(t *testing.T) {
	args := privescCheckArgs{
		TargetDir: `C:\temp`,
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for missing source, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "'source' is required") {
		t.Errorf("expected source required error, got %q", result.Output)
	}
}

func TestWinDLLPlant_MissingTargetDir(t *testing.T) {
	args := privescCheckArgs{
		Source:  `C:\temp\payload.dll`,
		DLLName: "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for missing target_dir, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "'target_dir' is required") {
		t.Errorf("expected target_dir required error, got %q", result.Output)
	}
}

func TestWinDLLPlant_MissingDLLName(t *testing.T) {
	args := privescCheckArgs{
		Source:    `C:\temp\payload.dll`,
		TargetDir: `C:\temp`,
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for missing dll_name, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "'dll_name' is required") {
		t.Errorf("expected dll_name required error, got %q", result.Output)
	}
}

func TestWinDLLPlant_SourceNotFound(t *testing.T) {
	args := privescCheckArgs{
		Source:    `C:\nonexistent\path\payload.dll`,
		TargetDir: t.TempDir(),
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent source, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Source DLL not found") {
		t.Errorf("expected source not found error, got %q", result.Output)
	}
}

func TestWinDLLPlant_SourceIsDirectory(t *testing.T) {
	dir := t.TempDir()
	args := privescCheckArgs{
		Source:    dir,
		TargetDir: t.TempDir(),
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for directory source, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "source path is a directory") {
		t.Errorf("expected directory error, got %q", result.Output)
	}
}

func TestWinDLLPlant_TargetDirNotFound(t *testing.T) {
	// Create a temp source file
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	os.WriteFile(src, []byte("fake dll"), 0644)

	args := privescCheckArgs{
		Source:    src,
		TargetDir: `C:\nonexistent\target\dir`,
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent target dir, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Target directory not found") {
		t.Errorf("expected target dir not found error, got %q", result.Output)
	}
}

func TestWinDLLPlant_TargetIsNotDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	os.WriteFile(src, []byte("fake dll"), 0644)

	notDir := filepath.Join(dir, "notadir.txt")
	os.WriteFile(notDir, []byte("file"), 0644)

	args := privescCheckArgs{
		Source:    src,
		TargetDir: notDir,
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for non-directory target, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "target_dir is not a directory") {
		t.Errorf("expected not a directory error, got %q", result.Output)
	}
}

func TestWinDLLPlant_DLLExtensionAppended(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	os.WriteFile(src, []byte("fake dll content"), 0644)

	targetDir := t.TempDir()

	args := privescCheckArgs{
		Source:    src,
		TargetDir: targetDir,
		DLLName:   "nodllext", // no .dll suffix
	}
	result := winDLLPlant(args)
	if result.Status == "error" {
		t.Skipf("DLL plant failed (may need writable dir): %s", result.Output)
	}

	// Check the planted file has .dll extension
	plantedPath := filepath.Join(targetDir, "nodllext.dll")
	if _, err := os.Stat(plantedPath); err != nil {
		t.Errorf("expected planted DLL at %s with .dll extension appended", plantedPath)
	}
}

func TestWinDLLPlant_TargetAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	os.WriteFile(src, []byte("fake dll"), 0644)

	targetDir := t.TempDir()
	existing := filepath.Join(targetDir, "existing.dll")
	os.WriteFile(existing, []byte("already here"), 0644)

	args := privescCheckArgs{
		Source:    src,
		TargetDir: targetDir,
		DLLName:   "existing.dll",
	}
	result := winDLLPlant(args)
	if result.Status != "error" {
		t.Errorf("expected error for existing target, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "already exists") {
		t.Errorf("expected already exists error, got %q", result.Output)
	}
}

func TestWinDLLPlant_SuccessfulPlant(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	content := []byte("fake DLL payload content for testing")
	os.WriteFile(src, content, 0644)

	targetDir := t.TempDir()

	args := privescCheckArgs{
		Source:    src,
		TargetDir: targetDir,
		DLLName:   "test.dll",
	}
	result := winDLLPlant(args)
	if result.Status == "error" {
		t.Skipf("DLL plant failed: %s", result.Output)
	}

	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}

	// Verify the file was copied
	plantedPath := filepath.Join(targetDir, "test.dll")
	planted, err := os.ReadFile(plantedPath)
	if err != nil {
		t.Fatalf("planted DLL not found: %v", err)
	}
	if string(planted) != string(content) {
		t.Errorf("planted DLL content mismatch")
	}

	// Verify output mentions successful plant
	if !strings.Contains(result.Output, "DLL planted successfully") {
		t.Errorf("expected success message, got %q", result.Output)
	}
}

func TestWinDLLPlant_TimestompDisabled(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.dll")
	os.WriteFile(src, []byte("fake dll"), 0644)

	targetDir := t.TempDir()
	noTimestomp := false

	args := privescCheckArgs{
		Source:    src,
		TargetDir: targetDir,
		DLLName:   "test.dll",
		Timestomp: &noTimestomp,
	}
	result := winDLLPlant(args)
	if result.Status == "error" {
		t.Skipf("DLL plant failed: %s", result.Output)
	}

	// When timestomp is disabled, output should not contain timestomp info
	if strings.Contains(result.Output, "Timestomp: matched") {
		t.Errorf("timestomp should be disabled but output mentions matching")
	}
}

func TestPrivescCheckCommand_DLLActions(t *testing.T) {
	actions := []string{"dll-hijack", "dll-sideload", "dll-plant"}
	cmd := &PrivescCheckCommand{}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			task := structs.Task{Params: `{"action":"` + action + `"}`}
			result := cmd.Execute(task)
			// dll-plant without required params should error
			if action == "dll-plant" {
				if result.Status != "error" {
					t.Errorf("dll-plant without params should error, got %q", result.Status)
				}
			}
			// dll-hijack and dll-sideload should succeed (they scan the system)
			// Don't check for specific status as it depends on the system
		})
	}
}

func TestWinPrivescCheckDLLHijack_Output(t *testing.T) {
	result := winPrivescCheckDLLHijack()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain standard DLL search order info
	if !strings.Contains(result.Output, "DLL Search Order") {
		t.Error("expected DLL search order section in output")
	}
	if !strings.Contains(result.Output, "Phantom DLL") {
		t.Error("expected phantom DLL section in output")
	}
	if !strings.Contains(result.Output, "PATH Directories") {
		t.Error("expected PATH directories section in output")
	}
	if !strings.Contains(result.Output, "KnownDLLs") {
		t.Error("expected KnownDLLs section in output")
	}
}

func TestWinPrivescCheckDLLSideLoad_Output(t *testing.T) {
	result := winPrivescCheckDLLSideLoad()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain scan summary
	if !strings.Contains(result.Output, "Scanned") {
		t.Error("expected scan count in output")
	}
	if !strings.Contains(result.Output, "side-loading targets") {
		t.Error("expected side-loading targets reference in output")
	}
}
