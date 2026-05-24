package commands

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanCertutilStaging(t *testing.T) {
	// Create a temp file to stage
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.exe")
	content := []byte("MZ\x90\x00\x03\x00\x00\x00") // fake PE header
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	plan, err := planStaging(localPath, `C:\Windows\Temp\staged.exe`, stageCertutil)
	if err != nil {
		t.Fatal(err)
	}

	if plan.RemotePath != `C:\Windows\Temp\staged.exe` {
		t.Errorf("expected remote path C:\\Windows\\Temp\\staged.exe, got %s", plan.RemotePath)
	}

	if len(plan.WriteCommands) == 0 {
		t.Error("expected at least one write command")
	}

	// First write command should use > (overwrite), not >>
	if !strings.Contains(plan.WriteCommands[0], " > ") {
		t.Error("first write command should use > redirect")
	}

	// Verify the base64 content is present
	b64 := base64.StdEncoding.EncodeToString(content)
	if !strings.Contains(plan.WriteCommands[0], b64) {
		t.Error("write command should contain base64 of file content")
	}

	// Should have a decode command
	if plan.DecodeCommand == "" {
		t.Error("certutil staging should have a decode command")
	}
	if !strings.Contains(plan.DecodeCommand, "certutil") {
		t.Error("decode command should use certutil")
	}

	// Should have cleanup commands
	if len(plan.CleanupCommands) < 2 {
		t.Errorf("expected at least 2 cleanup commands (b64 + binary), got %d", len(plan.CleanupCommands))
	}
}

func TestPlanPowerShellStaging(t *testing.T) {
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.dll")
	content := []byte("small payload data")
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	plan, err := planStaging(localPath, `C:\Temp\payload.dll`, stagePowerShell)
	if err != nil {
		t.Fatal(err)
	}

	if plan.RemotePath != `C:\Temp\payload.dll` {
		t.Errorf("expected remote path C:\\Temp\\payload.dll, got %s", plan.RemotePath)
	}

	// PowerShell staging should be a single write command (for small files)
	if len(plan.WriteCommands) != 1 {
		t.Errorf("expected 1 write command for small PS staging, got %d", len(plan.WriteCommands))
	}

	if !strings.Contains(plan.WriteCommands[0], "powershell") {
		t.Error("write command should use powershell")
	}

	if !strings.Contains(plan.WriteCommands[0], "WriteAllBytes") {
		t.Error("write command should use [IO.File]::WriteAllBytes")
	}

	// No decode command for PowerShell method
	if plan.DecodeCommand != "" {
		t.Error("PowerShell staging should not have a separate decode command")
	}

	// Should have cleanup commands
	if len(plan.CleanupCommands) == 0 {
		t.Error("expected cleanup commands")
	}
}

func TestPlanStagingDefaultRemotePath(t *testing.T) {
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "agent.exe")
	if err := os.WriteFile(localPath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	plan, err := planStaging(localPath, "", stageCertutil)
	if err != nil {
		t.Fatal(err)
	}

	// Should generate a path under C:\Windows\Temp with .exe extension
	if !strings.HasPrefix(plan.RemotePath, `C:\Windows\Temp\`) {
		t.Errorf("default remote path should be under C:\\Windows\\Temp, got %s", plan.RemotePath)
	}
	if !strings.HasSuffix(plan.RemotePath, ".exe") {
		t.Errorf("should preserve .exe extension, got %s", plan.RemotePath)
	}
}

func TestPlanStagingEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "empty.exe")
	if err := os.WriteFile(localPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := planStaging(localPath, `C:\target.exe`, stageCertutil)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestPlanStagingMissingFile(t *testing.T) {
	_, err := planStaging("/nonexistent/file.exe", `C:\target.exe`, stageCertutil)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestCertutilChunking(t *testing.T) {
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "large.bin")

	// Create a file large enough to require multiple chunks
	// Each chunk is ~maxCmdLen - overhead (~6940 chars of base64 = ~5200 bytes)
	largeData := make([]byte, 20000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	if err := os.WriteFile(localPath, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	plan, err := planStaging(localPath, `C:\staged.bin`, stageCertutil)
	if err != nil {
		t.Fatal(err)
	}

	// 20000 bytes -> ~26668 base64 chars -> should need multiple chunks
	if len(plan.WriteCommands) < 2 {
		t.Errorf("expected multiple write commands for large file, got %d", len(plan.WriteCommands))
	}

	// First command should use > (overwrite)
	if !strings.Contains(plan.WriteCommands[0], " > ") {
		t.Error("first command should use > redirect")
	}

	// Subsequent commands should use >> (append)
	for i := 1; i < len(plan.WriteCommands); i++ {
		if !strings.Contains(plan.WriteCommands[i], " >> ") {
			t.Errorf("command %d should use >> redirect", i)
		}
	}

	// Reconstruct and verify the base64 is complete
	var allB64 strings.Builder
	for _, cmd := range plan.WriteCommands {
		// Extract base64 content between "echo " and " >" or " >>"
		start := strings.Index(cmd, "echo ") + 5
		end := strings.LastIndex(cmd, " >")
		if start < 5 || end < 0 {
			t.Fatalf("cannot parse write command: %s", cmd)
		}
		allB64.WriteString(cmd[start:end])
	}

	decoded, err := base64.StdEncoding.DecodeString(allB64.String())
	if err != nil {
		t.Fatalf("reconstructed base64 is invalid: %v", err)
	}

	if len(decoded) != len(largeData) {
		t.Errorf("decoded size %d != original %d", len(decoded), len(largeData))
	}
}

func TestPowerShellFallbackForLargeFiles(t *testing.T) {
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "large.bin")

	// Create a file larger than maxPSBase64 limit
	largeData := make([]byte, 200000) // 200KB > 150KB limit
	if err := os.WriteFile(localPath, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	plan, err := planStaging(localPath, `C:\staged.bin`, stagePowerShell)
	if err != nil {
		t.Fatal(err)
	}

	// Should fall back to certutil for large files
	if plan.DecodeCommand == "" {
		t.Error("large files should fall back to certutil (which has a decode command)")
	}
	if !strings.Contains(plan.DecodeCommand, "certutil") {
		t.Error("fallback should use certutil decode")
	}
}

func TestParseStagingMethod(t *testing.T) {
	tests := []struct {
		input    string
		expected stagingMethod
	}{
		{"certutil", stageCertutil},
		{"powershell", stagePowerShell},
		{"ps", stagePowerShell},
		{"", stageCertutil},
		{"unknown", stageCertutil},
	}

	for _, tt := range tests {
		got := parseStagingMethod(tt.input)
		if got != tt.expected {
			t.Errorf("parseStagingMethod(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestRandomStagingName(t *testing.T) {
	names := make(map[string]bool)
	for i := 0; i < 100; i++ {
		name := randomStagingName()
		if len(name) < 4 {
			t.Errorf("staging name too short: %s", name)
		}
		names[name] = true
	}
	// Should generate diverse names
	if len(names) < 50 {
		t.Errorf("expected more unique names, got %d out of 100", len(names))
	}
}
