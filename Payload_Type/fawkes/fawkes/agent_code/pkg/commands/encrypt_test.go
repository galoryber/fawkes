package commands

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEncryptNoParams(t *testing.T) {
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestEncryptNoPath(t *testing.T) {
	params, _ := json.Marshal(encryptArgs{Action: "encrypt"})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "path is required") {
		t.Fatalf("expected path required error, got: %s", result.Output)
	}
}

func TestEncryptInvalidAction(t *testing.T) {
	params, _ := json.Marshal(encryptArgs{Action: "invalid", Path: "/tmp/test"})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "encrypt, decrypt") {
		t.Fatalf("expected action error, got: %s", result.Output)
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "secret.txt")
	encFile := filepath.Join(dir, "secret.txt.enc")
	decFile := filepath.Join(dir, "secret.txt.dec")

	original := "This is secret data that needs encryption!\nLine 2\nLine 3"
	os.WriteFile(inputFile, []byte(original), 0644)

	// Encrypt
	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("encrypt failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Encrypted:") {
		t.Fatalf("expected encrypt output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "AES-256-GCM") {
		t.Fatalf("expected algorithm in output, got: %s", result.Output)
	}

	// Extract key from output
	var key string
	for _, line := range strings.Split(result.Output, "\n") {
		if strings.HasPrefix(line, "Key (base64): ") {
			key = strings.TrimPrefix(line, "Key (base64): ")
			break
		}
	}
	if key == "" {
		t.Fatalf("could not extract key from output: %s", result.Output)
	}

	// Verify encrypted file exists and is different from original
	encData, err := os.ReadFile(encFile)
	if err != nil {
		t.Fatalf("encrypted file not found: %v", err)
	}
	if string(encData) == original {
		t.Fatal("encrypted data should differ from original")
	}

	// Decrypt
	params, _ = json.Marshal(encryptArgs{Action: "decrypt", Path: encFile, Output: decFile, Key: key})
	result = cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("decrypt failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Decrypted:") {
		t.Fatalf("expected decrypt output, got: %s", result.Output)
	}

	// Verify decrypted matches original
	decData, err := os.ReadFile(decFile)
	if err != nil {
		t.Fatalf("decrypted file not found: %v", err)
	}
	if string(decData) != original {
		t.Fatalf("decrypted data doesn't match original.\nExpected: %s\nGot: %s", original, string(decData))
	}
}

func TestEncryptWithProvidedKey(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "data.bin")
	encFile := filepath.Join(dir, "data.bin.enc")
	decFile := filepath.Join(dir, "data.bin.dec")

	// Generate a known key
	key := make([]byte, 32)
	rand.Read(key)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	// Write test data
	original := make([]byte, 1024)
	rand.Read(original)
	os.WriteFile(inputFile, original, 0644)

	// Encrypt with provided key
	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile, Key: keyB64})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("encrypt failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, keyB64) {
		t.Fatalf("expected provided key in output, got: %s", result.Output)
	}

	// Decrypt
	params, _ = json.Marshal(encryptArgs{Action: "decrypt", Path: encFile, Output: decFile, Key: keyB64})
	result = cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("decrypt failed: %s", result.Output)
	}

	decData, err := os.ReadFile(decFile)
	if err != nil {
		t.Fatalf("decrypted file not found: %v", err)
	}
	if len(decData) != len(original) {
		t.Fatalf("decrypted size mismatch: %d vs %d", len(decData), len(original))
	}
	for i := range original {
		if decData[i] != original[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
	}
}

func TestEncryptWrongKey(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "secret.txt")
	encFile := filepath.Join(dir, "secret.txt.enc")

	os.WriteFile(inputFile, []byte("secret data"), 0644)

	// Encrypt
	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("encrypt failed: %s", result.Output)
	}

	// Try decrypt with wrong key
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	wrongKeyB64 := base64.StdEncoding.EncodeToString(wrongKey)

	params, _ = json.Marshal(encryptArgs{Action: "decrypt", Path: encFile, Key: wrongKeyB64})
	result = cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error with wrong key, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "wrong key") {
		t.Fatalf("expected wrong key error, got: %s", result.Output)
	}
}

func TestDecryptNoKey(t *testing.T) {
	dir := t.TempDir()
	encFile := filepath.Join(dir, "data.enc")
	os.WriteFile(encFile, []byte("fake encrypted data"), 0644)

	params, _ := json.Marshal(encryptArgs{Action: "decrypt", Path: encFile})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "key is required") {
		t.Fatalf("expected key required error, got: %s", result.Output)
	}
}

func TestEncryptBadKey(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "data.txt")
	os.WriteFile(inputFile, []byte("test data"), 0644)

	// Wrong key size (16 bytes instead of 32)
	shortKey := make([]byte, 16)
	rand.Read(shortKey)
	shortKeyB64 := base64.StdEncoding.EncodeToString(shortKey)

	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile, Key: shortKeyB64})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error for short key, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "key must be 32 bytes") {
		t.Fatalf("expected key size error, got: %s", result.Output)
	}
}

func TestEncryptNonexistentFile(t *testing.T) {
	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: "/nonexistent/file.txt"})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error, got %s: %s", result.Status, result.Output)
	}
}

func TestEncryptCustomOutput(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "input.txt")
	customOut := filepath.Join(dir, "custom_output.dat")

	os.WriteFile(inputFile, []byte("custom output test"), 0644)

	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile, Output: customOut})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("encrypt failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "custom_output.dat") {
		t.Fatalf("expected custom output path in result, got: %s", result.Output)
	}

	if _, err := os.Stat(customOut); err != nil {
		t.Fatalf("custom output file not created: %v", err)
	}
}

func TestEncryptEmptyFile(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "empty.txt")
	os.WriteFile(inputFile, []byte{}, 0644)

	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("encrypt failed on empty file: %s", result.Output)
	}

	// Extract key and decrypt
	var key string
	for _, line := range strings.Split(result.Output, "\n") {
		if strings.HasPrefix(line, "Key (base64): ") {
			key = strings.TrimPrefix(line, "Key (base64): ")
			break
		}
	}

	encFile := filepath.Join(dir, "empty.txt.enc")
	decFile := filepath.Join(dir, "empty.txt.dec")
	params, _ = json.Marshal(encryptArgs{Action: "decrypt", Path: encFile, Output: decFile, Key: key})
	result = cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("decrypt failed on empty file: %s", result.Output)
	}

	decData, _ := os.ReadFile(decFile)
	if len(decData) != 0 {
		t.Fatalf("expected empty decrypted file, got %d bytes", len(decData))
	}
}

// --- Batch encrypt/decrypt tests (T1486 ransomware simulation) ---

func TestEncryptFilesNoConfirm(t *testing.T) {
	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{Action: "encrypt-files", Path: "/tmp/*.txt"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "SIMULATE") {
		t.Errorf("expected SIMULATE safety gate error, got: %s", result.Output)
	}
}

func TestEncryptFilesMissingPath(t *testing.T) {
	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{Action: "encrypt-files", Confirm: "SIMULATE"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestEncryptFilesDecryptFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.txt": "content A",
		"b.txt": "content B",
		"c.txt": "content C",
	}
	for name, content := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	}

	cmd := &EncryptCommand{}

	// Encrypt batch
	params, _ := json.Marshal(encryptArgs{
		Action: "encrypt-files", Path: filepath.Join(dir, "*.txt"), Confirm: "SIMULATE",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("encrypt-files failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files encrypted: 3/3") {
		t.Errorf("expected 3/3 encrypted, got: %s", result.Output)
	}

	// Extract recovery key
	var key string
	for _, line := range strings.Split(result.Output, "\n") {
		if strings.HasPrefix(line, "Recovery Key (base64): ") {
			key = strings.TrimPrefix(line, "Recovery Key (base64): ")
			break
		}
	}
	if key == "" {
		t.Fatal("no recovery key in output")
	}

	// Verify .fawkes files exist and originals removed
	for name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("original %s should be deleted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, name+".fawkes")); err != nil {
			t.Errorf(".fawkes file missing for %s", name)
		}
	}

	// Decrypt batch
	params, _ = json.Marshal(encryptArgs{Action: "decrypt-files", Path: dir, Key: key})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("decrypt-files failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files decrypted: 3/3") {
		t.Errorf("expected 3/3 decrypted, got: %s", result.Output)
	}

	// Verify content restored
	for name, content := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("restored %s not found: %v", name, err)
			continue
		}
		if string(data) != content {
			t.Errorf("restored %s content mismatch: got %q, want %q", name, data, content)
		}
	}
}

func TestEncryptFilesMaxFilesLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".txt"), []byte("data"), 0644)
	}

	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{
		Action: "encrypt-files", Path: filepath.Join(dir, "*.txt"),
		Confirm: "SIMULATE", MaxFiles: 3,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "max_files") {
		t.Errorf("expected max_files error, got: %s", result.Output)
	}
}

func TestEncryptFilesSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "new.txt"), []byte("new"), 0644)
	os.WriteFile(filepath.Join(dir, "old.txt.fawkes"), []byte("already encrypted"), 0644)

	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{
		Action: "encrypt-files", Path: filepath.Join(dir, "*"), Confirm: "SIMULATE",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("failed: %s", result.Output)
	}
	// Should encrypt only new.txt
	if !strings.Contains(result.Output, "Files encrypted: 1/1") {
		t.Errorf("expected 1/1 encrypted, got: %s", result.Output)
	}
}

func TestDecryptFilesMissingKey(t *testing.T) {
	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{Action: "decrypt-files", Path: "/tmp"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "key required") {
		t.Errorf("expected key error, got: %s", result.Output)
	}
}

func TestDecryptFilesWrongKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("content"), 0644)

	cmd := &EncryptCommand{}
	params, _ := json.Marshal(encryptArgs{
		Action: "encrypt-files", Path: filepath.Join(dir, "*.txt"), Confirm: "SIMULATE",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal("encrypt failed")
	}

	// Decrypt with wrong key — should report errors but succeed (partial decrypt)
	wrongKey := make([]byte, 32)
	params, _ = json.Marshal(encryptArgs{
		Action: "decrypt-files", Path: dir,
		Key: base64.StdEncoding.EncodeToString(wrongKey),
	})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("should succeed with error report: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Errors") {
		t.Errorf("expected errors for wrong key, got: %s", result.Output)
	}
}

func TestDecryptAutoOutputPath(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "data.txt")
	os.WriteFile(inputFile, []byte("auto path test"), 0644)

	// Encrypt
	params, _ := json.Marshal(encryptArgs{Action: "encrypt", Path: inputFile})
	cmd := &EncryptCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("encrypt failed: %s", result.Output)
	}

	var key string
	for _, line := range strings.Split(result.Output, "\n") {
		if strings.HasPrefix(line, "Key (base64): ") {
			key = strings.TrimPrefix(line, "Key (base64): ")
			break
		}
	}

	// Decrypt with auto output (should strip .enc)
	encFile := filepath.Join(dir, "data.txt.enc")
	params, _ = json.Marshal(encryptArgs{Action: "decrypt", Path: encFile, Key: key})

	// Remove the original so the auto-path can write to data.txt
	os.Remove(inputFile)

	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("decrypt failed: %s", result.Output)
	}

	// Should have created data.txt (stripped .enc)
	if !strings.Contains(result.Output, "data.txt") {
		t.Fatalf("expected auto output path, got: %s", result.Output)
	}
}
