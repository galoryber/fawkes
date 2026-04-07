package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello, World! This is a test of AES-256-GCM encryption.")
	ciphertext, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	decrypted, err := decryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("decrypted text does not match original")
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("secret data")
	ciphertext, _ := encryptAESGCM(key1, plaintext)

	_, err := decryptAESGCM(key2, ciphertext)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestEncryptDecryptEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	ciphertext, err := encryptAESGCM(key, []byte{})
	if err != nil {
		t.Fatalf("encrypt empty data: %v", err)
	}

	decrypted, err := decryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt empty data: %v", err)
	}

	if len(decrypted) != 0 {
		t.Error("decrypted empty data should be empty")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	_, err := decryptAESGCM(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("decrypt too-short data should fail")
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// 1MB of random data
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	ciphertext, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt large data: %v", err)
	}

	decrypted, err := decryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt large data: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("large data roundtrip failed")
	}
}

func TestCompressStage(t *testing.T) {
	// Create temp directory with test files
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("hello world"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("secret data"), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "subdir", "file3.txt"), []byte("nested content"), 0644)

	stagingDir := t.TempDir()

	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "stage",
		Path:   tmpDir,
		Output: stagingDir,
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("stage failed: %s", result.Output)
	}

	// Parse output metadata
	var meta stageMetadata
	if err := json.Unmarshal([]byte(result.Output), &meta); err != nil {
		t.Fatalf("failed to parse stage metadata: %v", err)
	}

	if meta.FileCount != 3 {
		t.Errorf("expected 3 files staged, got %d", meta.FileCount)
	}
	if meta.EncryptionKey == "" {
		t.Error("encryption key should not be empty")
	}
	if meta.ArchivePath == "" {
		t.Error("archive path should not be empty")
	}
	if meta.SHA256 == "" {
		t.Error("SHA256 hash should not be empty")
	}

	// Verify the encrypted archive exists and can be decrypted
	encData, err := os.ReadFile(meta.ArchivePath)
	if err != nil {
		t.Fatalf("failed to read encrypted archive: %v", err)
	}

	key, err := hex.DecodeString(meta.EncryptionKey)
	if err != nil {
		t.Fatalf("failed to decode key: %v", err)
	}

	decrypted, err := decryptAESGCM(key, encData)
	if err != nil {
		t.Fatalf("failed to decrypt archive: %v", err)
	}

	// Decrypted data should be a valid zip
	if len(decrypted) < 4 || string(decrypted[:2]) != "PK" {
		t.Error("decrypted data is not a valid zip archive")
	}
}

func TestCompressStageWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "doc.txt"), []byte("text"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "image.png"), []byte("png"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "data.csv"), []byte("csv"), 0644)

	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action:  "stage",
		Path:    tmpDir,
		Pattern: "*.txt",
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("stage with pattern failed: %s", result.Output)
	}

	var meta stageMetadata
	json.Unmarshal([]byte(result.Output), &meta)

	if meta.FileCount != 1 {
		t.Errorf("expected 1 file (*.txt pattern), got %d", meta.FileCount)
	}
}

func TestCompressStageEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "stage",
		Path:   tmpDir,
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("staging empty directory should return error")
	}
}

func TestCompressStageNoPath(t *testing.T) {
	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "stage",
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("staging without path should return error")
	}
}
