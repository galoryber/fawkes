package files

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSaveAndGetTransferState(t *testing.T) {
	// Clean up any lingering state
	ClearTransferState("/test/file.txt")

	state := &TransferState{
		FileID:      "abc123",
		FullPath:    "/test/file.txt",
		Direction:   TransferDownload,
		TotalChunks: 10,
		LastChunk:   5,
		BytesSoFar:  2560000,
	}

	SaveTransferState(state)

	got := GetTransferState("/test/file.txt", TransferDownload)
	if got == nil {
		t.Fatal("Expected state, got nil")
	}
	if got.FileID != "abc123" {
		t.Errorf("FileID = %s, want abc123", got.FileID)
	}
	if got.LastChunk != 5 {
		t.Errorf("LastChunk = %d, want 5", got.LastChunk)
	}
	if got.TotalChunks != 10 {
		t.Errorf("TotalChunks = %d, want 10", got.TotalChunks)
	}
	if got.BytesSoFar != 2560000 {
		t.Errorf("BytesSoFar = %d, want 2560000", got.BytesSoFar)
	}

	// Clean up
	ClearTransferState("/test/file.txt")
}

func TestGetTransferState_WrongDirection(t *testing.T) {
	ClearTransferState("/test/upload.txt")

	state := &TransferState{
		FileID:    "xyz",
		FullPath:  "/test/upload.txt",
		Direction: TransferUpload,
	}
	SaveTransferState(state)

	// Request with wrong direction should return nil
	got := GetTransferState("/test/upload.txt", TransferDownload)
	if got != nil {
		t.Error("Expected nil for wrong direction")
	}

	// Correct direction should return state
	got = GetTransferState("/test/upload.txt", TransferUpload)
	if got == nil {
		t.Error("Expected state for correct direction")
	}

	ClearTransferState("/test/upload.txt")
}

func TestGetTransferState_NotFound(t *testing.T) {
	got := GetTransferState("/nonexistent/path", TransferDownload)
	if got != nil {
		t.Error("Expected nil for nonexistent path")
	}
}

func TestClearTransferState(t *testing.T) {
	state := &TransferState{
		FileID:   "clear-me",
		FullPath: "/test/clear.txt",
	}
	SaveTransferState(state)

	ClearTransferState("/test/clear.txt")

	got := GetTransferState("/test/clear.txt", TransferDownload)
	if got != nil {
		t.Error("Expected nil after clearing")
	}
}

func TestSaveTransferState_Overwrite(t *testing.T) {
	path := "/test/overwrite.txt"
	ClearTransferState(path)

	SaveTransferState(&TransferState{
		FileID:    "first",
		FullPath:  path,
		LastChunk: 3,
	})
	SaveTransferState(&TransferState{
		FileID:    "second",
		FullPath:  path,
		LastChunk: 7,
	})

	got := GetTransferState(path, TransferDownload)
	if got == nil {
		t.Fatal("Expected state")
	}
	if got.FileID != "second" {
		t.Errorf("FileID = %s, want second (latest)", got.FileID)
	}
	if got.LastChunk != 7 {
		t.Errorf("LastChunk = %d, want 7", got.LastChunk)
	}

	ClearTransferState(path)
}

func TestStreamingHasher_Basic(t *testing.T) {
	h := NewStreamingHasher()
	h.Write([]byte("hello"))
	h.Write([]byte(" world"))

	// Compare against manual SHA256
	hasher := sha256.New()
	hasher.Write([]byte("hello world"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if got := h.Sum(); got != expected {
		t.Errorf("Sum() = %s, want %s", got, expected)
	}
	if h.BytesHashed() != 11 {
		t.Errorf("BytesHashed() = %d, want 11", h.BytesHashed())
	}
}

func TestStreamingHasher_Empty(t *testing.T) {
	h := NewStreamingHasher()

	// SHA256 of empty string
	hasher := sha256.New()
	expected := hex.EncodeToString(hasher.Sum(nil))

	if got := h.Sum(); got != expected {
		t.Errorf("Sum() = %s, want %s", got, expected)
	}
	if h.BytesHashed() != 0 {
		t.Errorf("BytesHashed() = %d, want 0", h.BytesHashed())
	}
}

func TestStreamingHasher_LargeChunks(t *testing.T) {
	h := NewStreamingHasher()

	// Write 1MB in 4KB chunks
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	total := 0
	for i := 0; i < 256; i++ {
		h.Write(chunk)
		total += len(chunk)
	}

	if h.BytesHashed() != int64(total) {
		t.Errorf("BytesHashed() = %d, want %d", h.BytesHashed(), total)
	}

	// The hash should be non-empty and deterministic
	hash1 := h.Sum()
	if hash1 == "" {
		t.Error("Sum() should not be empty")
	}
	if len(hash1) != 64 { // SHA256 = 32 bytes = 64 hex chars
		t.Errorf("Sum() length = %d, want 64", len(hash1))
	}
}
