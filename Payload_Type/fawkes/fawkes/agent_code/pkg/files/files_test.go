package files

import (
	"math"
	"strings"
	"sync"
	"testing"
)

// --- generateUUID Tests ---

func TestGenerateUUID_NoDashes(t *testing.T) {
	id := generateUUID()
	if strings.Contains(id, "-") {
		t.Errorf("generateUUID() = %q, should not contain dashes", id)
	}
}

func TestGenerateUUID_Length(t *testing.T) {
	id := generateUUID()
	// Standard UUID is 36 chars (32 hex + 4 dashes), without dashes = 32
	if len(id) != 32 {
		t.Errorf("generateUUID() length = %d, want 32", len(id))
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateUUID()
		if seen[id] {
			t.Fatalf("generateUUID() produced duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestGenerateUUID_HexOnly(t *testing.T) {
	id := generateUUID()
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateUUID() contains non-hex char %q in %q", string(c), id)
		}
	}
}

// --- FILE_CHUNK_SIZE Tests ---

func TestFileChunkSize_Value(t *testing.T) {
	if FILE_CHUNK_SIZE != 512000 {
		t.Errorf("FILE_CHUNK_SIZE = %d, want 512000", FILE_CHUNK_SIZE)
	}
}

// --- Chunk Calculation Tests ---
// These test the same math used in sendFile.go for chunk count

func TestChunkCalculation_SmallFile(t *testing.T) {
	size := int64(1024) // 1 KB
	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	if chunks != 1 {
		t.Errorf("1KB file should be 1 chunk, got %d", chunks)
	}
}

func TestChunkCalculation_ExactChunk(t *testing.T) {
	size := int64(FILE_CHUNK_SIZE) // Exactly 512000 bytes
	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	if chunks != 1 {
		t.Errorf("512000 byte file should be 1 chunk, got %d", chunks)
	}
}

func TestChunkCalculation_MultiChunk(t *testing.T) {
	size := int64(FILE_CHUNK_SIZE + 1) // 512001 bytes
	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	if chunks != 2 {
		t.Errorf("512001 byte file should be 2 chunks, got %d", chunks)
	}
}

func TestChunkCalculation_LargeFile(t *testing.T) {
	size := int64(10 * 1024 * 1024) // 10 MB
	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	expected := uint64(math.Ceil(float64(10*1024*1024) / 512000))
	if chunks != expected {
		t.Errorf("10MB file should be %d chunks, got %d", expected, chunks)
	}
}

func TestChunkCalculation_ZeroFile(t *testing.T) {
	size := int64(0)
	chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
	if chunks != 0 {
		t.Errorf("0 byte file should be 0 chunks, got %d", chunks)
	}
}

// --- Part Size Calculation Tests ---
// Tests the same math used in sendFile.go for determining chunk sizes

func TestPartSize_FirstChunk(t *testing.T) {
	size := int64(1000000) // ~1MB, 2 chunks
	i := uint64(0)
	partSize := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(i*FILE_CHUNK_SIZE))))
	if partSize != FILE_CHUNK_SIZE {
		t.Errorf("First chunk of 1MB file should be %d bytes, got %d", FILE_CHUNK_SIZE, partSize)
	}
}

func TestPartSize_LastChunk(t *testing.T) {
	size := int64(1000000) // ~1MB, 2 chunks
	i := uint64(1)
	partSize := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(i*FILE_CHUNK_SIZE))))
	expected := 1000000 - FILE_CHUNK_SIZE
	if partSize != expected {
		t.Errorf("Last chunk should be %d bytes, got %d", expected, partSize)
	}
}

func TestPartSize_SingleChunk(t *testing.T) {
	size := int64(100) // Small file, 1 chunk
	i := uint64(0)
	partSize := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(i*FILE_CHUNK_SIZE))))
	if partSize != 100 {
		t.Errorf("Single chunk of 100 byte file should be 100, got %d", partSize)
	}
}

// --- Initialize idempotency test ---
// Initialize() should be safe to call multiple times without spawning duplicate goroutines

func TestInitialize_Idempotent(t *testing.T) {
	// Reset the sync.Once for testing
	initOnce = sync.Once{}

	// Call Initialize multiple times — should not panic and channels should exist
	Initialize()
	Initialize()
	Initialize()

	// If we get here without panic or deadlock, the sync.Once guard works
	// Verify the channels are still functional (non-nil)
	if SendToMythicChannel == nil {
		t.Error("SendToMythicChannel is nil after Initialize()")
	}
	if GetFromMythicChannel == nil {
		t.Error("GetFromMythicChannel is nil after Initialize()")
	}
}

// --- Chunk boundary edge cases ---

func TestChunkCalculation_OneByteOverBoundary(t *testing.T) {
	// At each multiple of chunk size + 1 byte, we need one more chunk
	for multiplier := 1; multiplier <= 5; multiplier++ {
		size := int64(FILE_CHUNK_SIZE*multiplier + 1)
		chunks := uint64(math.Ceil(float64(size) / FILE_CHUNK_SIZE))
		expected := uint64(multiplier + 1)
		if chunks != expected {
			t.Errorf("Size %d should be %d chunks, got %d", size, expected, chunks)
		}
	}
}

func TestPartSize_MiddleChunks(t *testing.T) {
	// 3 full chunks + partial
	size := int64(FILE_CHUNK_SIZE*3 + 100)
	for i := uint64(0); i < 3; i++ {
		partSize := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(i*FILE_CHUNK_SIZE))))
		if partSize != FILE_CHUNK_SIZE {
			t.Errorf("Middle chunk %d should be %d bytes, got %d", i, FILE_CHUNK_SIZE, partSize)
		}
	}
	// Last chunk should be 100 bytes
	lastPart := int(math.Min(FILE_CHUNK_SIZE, float64(int64(size)-int64(3*FILE_CHUNK_SIZE))))
	if lastPart != 100 {
		t.Errorf("Last chunk should be 100 bytes, got %d", lastPart)
	}
}
