package files

import (
	"encoding/base64"
	"encoding/json"
	"fawkes/pkg/structs"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Helper: create a test task with Job and channels ---

func newTestTask(id string) *structs.Task {
	stop := 0
	job := &structs.Job{
		Stop:          &stop,
		SendResponses: make(chan structs.Response, 100),
		FileTransfers: make(map[string]chan json.RawMessage),
	}
	return &structs.Task{
		ID:  id,
		Job: job,
	}
}

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

// =============================================================================
// sendFileMessagesToMythic Tests
// =============================================================================

// Test: No data and no file => error response
func TestSendFile_NoDataNoFile(t *testing.T) {
	task := newTestTask("task-1")
	finished := make(chan int, 1)

	msg := structs.SendFileToMythicStruct{
		Task:             task,
		Data:             nil,
		File:             nil,
		FinishedTransfer: finished,
	}

	go sendFileMessagesToMythic(msg)

	// Should get an error response
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "No data and no file specified") {
			t.Errorf("Expected 'No data and no file' error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for error response")
	}

	// Should signal finished
	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished signal")
	}
}

// Test: Send small data (single chunk) with successful transfer
func TestSendFile_SmallDataSingleChunk(t *testing.T) {
	task := newTestTask("task-2")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("hello world test data")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FullPath:             "",
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// 1. Receive the initial announcement (total_chunks)
	var initResp structs.Response
	select {
	case initResp = <-task.Job.SendResponses:
		if initResp.Download == nil {
			t.Fatal("Expected Download field in initial response")
		}
		if initResp.Download.TotalChunks != 1 {
			t.Errorf("Expected 1 chunk, got %d", initResp.Download.TotalChunks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for initial response")
	}

	// 2. Send file_id response back (simulating Mythic's acknowledgment)
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "test-file-123"})
	fileTransferResp <- fileIDResp

	// 3. Receive the file_id user output
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "test-file-123") {
			t.Errorf("Expected file_id in output, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for file_id output")
	}

	// 4. Receive the chunk data
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download == nil {
			t.Fatal("Expected Download in chunk response")
		}
		if resp.Download.ChunkNum != 1 {
			t.Errorf("Expected chunk 1, got %d", resp.Download.ChunkNum)
		}
		if resp.Download.FileID != "test-file-123" {
			t.Errorf("Expected file_id 'test-file-123', got %s", resp.Download.FileID)
		}
		// Decode chunk data
		decoded, err := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if err != nil {
			t.Fatalf("Failed to decode chunk data: %v", err)
		}
		if string(decoded) != string(testData) {
			t.Errorf("Chunk data mismatch: got %q, want %q", decoded, testData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk data")
	}

	// 5. Send success response for the chunk
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp

	// 6. Should signal finished
	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished signal")
	}
}

// Test: Send data with multiple chunks
func TestSendFile_MultiChunk(t *testing.T) {
	task := newTestTask("task-3")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	// Create data slightly larger than one chunk
	testData := make([]byte, FILE_CHUNK_SIZE+100)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FullPath:             "/test/path.bin",
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// 1. Initial announcement
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.TotalChunks != 2 {
			t.Errorf("Expected 2 chunks, got %d", resp.Download.TotalChunks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for initial response")
	}

	// 2. Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "multi-chunk-file"})
	fileTransferResp <- fileIDResp

	// 3. Receive file_id output
	select {
	case <-task.Job.SendResponses:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 4. Receive and ack chunk 1
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.ChunkNum != 1 {
			t.Errorf("Expected chunk 1, got %d", resp.Download.ChunkNum)
		}
		decoded, _ := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if len(decoded) != FILE_CHUNK_SIZE {
			t.Errorf("Chunk 1 should be %d bytes, got %d", FILE_CHUNK_SIZE, len(decoded))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk 1")
	}

	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp

	// 5. Receive and ack chunk 2
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.ChunkNum != 2 {
			t.Errorf("Expected chunk 2, got %d", resp.Download.ChunkNum)
		}
		decoded, _ := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if len(decoded) != 100 {
			t.Errorf("Chunk 2 should be 100 bytes, got %d", len(decoded))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk 2")
	}

	fileTransferResp <- successResp

	// 6. Should finish
	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished")
	}
}

// Test: Send from os.File (real temp file)
func TestSendFile_FromOsFile(t *testing.T) {
	task := newTestTask("task-file")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	// Create a temp file with known content
	tmpFile, err := os.CreateTemp("", "sendfile-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := []byte("file content for testing")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		File:                 tmpFile,
		FullPath:             tmpFile.Name(),
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// 1. Initial announcement
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download == nil {
			t.Fatal("Expected Download in response")
		}
		if resp.Download.TotalChunks != 1 {
			t.Errorf("Expected 1 chunk, got %d", resp.Download.TotalChunks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 2. Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "file-id-osfile"})
	fileTransferResp <- fileIDResp

	// 3. Receive file_id output
	select {
	case <-task.Job.SendResponses:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 4. Receive chunk
	select {
	case resp := <-task.Job.SendResponses:
		decoded, _ := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if string(decoded) != string(content) {
			t.Errorf("File content mismatch: got %q, want %q", decoded, content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp

	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	tmpFile.Close()
}

// Test: Bad JSON response from Mythic during initial file_id exchange
func TestSendFile_BadJSONResponse(t *testing.T) {
	task := newTestTask("task-badjson")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-task.Job.SendResponses:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send invalid JSON
	fileTransferResp <- json.RawMessage(`{invalid json`)

	// Should get unmarshal error
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Error unmarshaling") {
			t.Errorf("Expected unmarshal error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Response without file_id should cause the loop to wait for another response
func TestSendFile_ResponseWithoutFileID(t *testing.T) {
	task := newTestTask("task-noid")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-task.Job.SendResponses:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for announcement")
	}

	// Send valid JSON but without file_id — should cause an error and finish
	noFileIDResp, _ := json.Marshal(map[string]interface{}{"status": "pending"})
	fileTransferResp <- noFileIDResp

	// Should receive error message about missing file_id
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "file_id") {
			t.Errorf("Expected file_id error message, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for error response")
	}

	// Transfer should finish with error
	select {
	case <-finished:
		// OK — transfer correctly aborted
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished signal")
	}
}

// Test: Chunk retry on non-success status
func TestSendFile_ChunkRetry(t *testing.T) {
	task := newTestTask("task-retry")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("retry data")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "retry-file"})
	fileTransferResp <- fileIDResp

	// Receive file_id output
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Receive chunk 1 (first attempt)
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send failure (non-success) — should cause retry
	failResp, _ := json.Marshal(map[string]interface{}{"status": "error"})
	fileTransferResp <- failResp

	// Should get chunk 1 again (retry)
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.ChunkNum != 1 {
			t.Errorf("Expected retry of chunk 1, got chunk %d", resp.Download.ChunkNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for retry")
	}

	// Now send success
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp

	select {
	case <-finished:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Bad JSON in chunk acknowledgment
func TestSendFile_BadJSONInChunkAck(t *testing.T) {
	task := newTestTask("task-badjsonack")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test data")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Skip announcement
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "badjsonack-file"})
	fileTransferResp <- fileIDResp

	// Skip file_id output
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Skip chunk data
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send bad JSON as chunk ack
	fileTransferResp <- json.RawMessage(`not json`)

	// Should get error
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Error unmarshaling") {
			t.Errorf("Expected unmarshal error, got: %s", resp.UserOutput)
		}
		if !resp.Completed {
			t.Error("Expected Completed=true on error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Screenshot flag propagated
func TestSendFile_ScreenshotFlag(t *testing.T) {
	task := newTestTask("task-screenshot")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("screenshot bytes")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		IsScreenshot:         true,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download == nil {
			t.Fatal("Expected Download in response")
		}
		if !resp.Download.IsScreenshot {
			t.Error("Expected IsScreenshot=true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Clean up: send file_id, get output, get chunk, ack, finish
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "screenshot-id"})
	fileTransferResp <- fileIDResp
	<-task.Job.SendResponses // file_id output
	<-task.Job.SendResponses // chunk
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp
	<-finished
}

// Test: Status updates sent when SendUserStatusUpdates is true
func TestSendFile_StatusUpdates(t *testing.T) {
	task := newTestTask("task-updates")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 20)

	// Create data large enough for 3 chunks (need >50% to trigger status updates)
	testData := make([]byte, FILE_CHUNK_SIZE*3)
	msg := structs.SendFileToMythicStruct{
		Task:                  task,
		Data:                  &testData,
		SendUserStatusUpdates: true,
		FinishedTransfer:      finished,
		FileTransferResponse:  fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Initial announcement
	<-task.Job.SendResponses

	// File ID
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "update-file"})
	fileTransferResp <- fileIDResp
	<-task.Job.SendResponses // file_id output

	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	gotStatusUpdate := false

	for i := 0; i < 3; i++ {
		// Drain all messages for this chunk (chunk data + possible status update)
		for {
			select {
			case resp := <-task.Job.SendResponses:
				if strings.Contains(resp.UserOutput, "File Transfer Update") {
					gotStatusUpdate = true
				}
				if resp.Download != nil {
					// This is the chunk data, ack it
					fileTransferResp <- successResp
					goto nextChunk
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Timed out")
			}
		}
	nextChunk:
	}

	if !gotStatusUpdate {
		t.Error("Expected at least one status update with SendUserStatusUpdates=true")
	}

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: FullPath is resolved to absolute path
func TestSendFile_FullPathResolved(t *testing.T) {
	task := newTestTask("task-path")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FullPath:             "relative/path.txt",
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	select {
	case resp := <-task.Job.SendResponses:
		// FullPath should be resolved to absolute
		if resp.Download.FullPath == "relative/path.txt" {
			t.Error("Expected FullPath to be resolved to absolute, but got relative path")
		}
		if !strings.HasSuffix(resp.Download.FullPath, "relative/path.txt") {
			t.Errorf("Resolved path should end with original path, got: %s", resp.Download.FullPath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Clean up
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "path-file"})
	fileTransferResp <- fileIDResp
	<-task.Job.SendResponses // file_id output
	<-task.Job.SendResponses // chunk
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp
	<-finished
}

// Test: Empty FullPath doesn't resolve
func TestSendFile_EmptyFullPath(t *testing.T) {
	task := newTestTask("task-emptypath")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FullPath:             "",
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.FullPath != "" {
			t.Errorf("Expected empty FullPath, got: %s", resp.Download.FullPath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Clean up
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "empty-path-file"})
	fileTransferResp <- fileIDResp
	<-task.Job.SendResponses // file_id output
	<-task.Job.SendResponses // chunk
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp
	<-finished
}

// =============================================================================
// sendUploadFileMessagesToMythic (getFile) Tests
// =============================================================================

// Test: Single-chunk file download from Mythic
func TestGetFile_SingleChunk(t *testing.T) {
	task := newTestTask("task-get-1")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	content := []byte("downloaded content from Mythic")
	encoded := base64.StdEncoding.EncodeToString(content)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "download-file-1",
		FullPath:             "/dest/path.txt",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// 1. Receive the upload request
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Upload == nil {
			t.Fatal("Expected Upload in response")
		}
		if resp.Upload.FileID != "download-file-1" {
			t.Errorf("Expected FileID 'download-file-1', got %s", resp.Upload.FileID)
		}
		if resp.Upload.ChunkNum != 1 {
			t.Errorf("Expected ChunkNum 1, got %d", resp.Upload.ChunkNum)
		}
		if resp.Upload.ChunkSize != 512000 {
			t.Errorf("Expected ChunkSize 512000, got %d", resp.Upload.ChunkSize)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 2. Send chunk response (single chunk, TotalChunks=1)
	chunkResp, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum:    1,
		ChunkData:   encoded,
		TotalChunks: 1,
	})
	fileTransferResp <- chunkResp

	// 3. Receive decoded chunk
	select {
	case data := <-receivedChunks:
		if string(data) != string(content) {
			t.Errorf("Chunk data mismatch: got %q, want %q", data, content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk data")
	}

	// 4. Receive done signal (empty slice)
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty done signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for done signal")
	}
}

// Test: Multi-chunk file download
func TestGetFile_MultiChunk(t *testing.T) {
	task := newTestTask("task-get-multi")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "multi-dl-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// 1. Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 2. Send first chunk (3 total)
	chunk1 := base64.StdEncoding.EncodeToString([]byte("chunk-1-data"))
	resp1, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: chunk1, TotalChunks: 3,
	})
	fileTransferResp <- resp1

	// 3. Receive chunk 1 data
	select {
	case data := <-receivedChunks:
		if string(data) != "chunk-1-data" {
			t.Errorf("Chunk 1 data mismatch: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 4. It should request chunk 2 — receive that request
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Upload.ChunkNum != 2 {
			t.Errorf("Expected request for chunk 2, got %d", resp.Upload.ChunkNum)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 5. Send chunk 2
	chunk2 := base64.StdEncoding.EncodeToString([]byte("chunk-2-data"))
	resp2, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 2, ChunkData: chunk2, TotalChunks: 3,
	})
	fileTransferResp <- resp2

	select {
	case data := <-receivedChunks:
		if string(data) != "chunk-2-data" {
			t.Errorf("Chunk 2 data mismatch: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 6. Request chunk 3
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 7. Send chunk 3
	chunk3 := base64.StdEncoding.EncodeToString([]byte("chunk-3-data"))
	resp3, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 3, ChunkData: chunk3, TotalChunks: 3,
	})
	fileTransferResp <- resp3

	select {
	case data := <-receivedChunks:
		if string(data) != "chunk-3-data" {
			t.Errorf("Chunk 3 data mismatch: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// 8. Done signal
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty done signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Bad JSON response from Mythic
func TestGetFile_BadJSON(t *testing.T) {
	task := newTestTask("task-get-badjson")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "bad-json-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send bad JSON
	fileTransferResp <- json.RawMessage(`{broken json`)

	// Should get error response
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Failed to parse") {
			t.Errorf("Expected parse error, got: %s", resp.UserOutput)
		}
		if !resp.Completed {
			t.Error("Expected Completed=true on error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Should send empty chunk to signal done
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty error signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Invalid base64 in chunk data
func TestGetFile_InvalidBase64(t *testing.T) {
	task := newTestTask("task-get-b64")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "b64-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send response with invalid base64
	badResp, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: "not!valid@base64", TotalChunks: 1,
	})
	fileTransferResp <- badResp

	// Should get error
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Failed to parse") {
			t.Errorf("Expected base64 parse error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Should send empty signal
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty error signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Status updates during multi-chunk download
func TestGetFile_StatusUpdates(t *testing.T) {
	task := newTestTask("task-get-status")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 20)

	msg := structs.GetFileFromMythicStruct{
		Task:                  task,
		FileID:                "status-file",
		SendUserStatusUpdates: true,
		ReceivedChunkChannel:  receivedChunks,
		FileTransferResponse:  fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial upload request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	chunk := base64.StdEncoding.EncodeToString([]byte("data"))
	gotFetchStatus := false

	// Send all 3 chunks and collect all messages from both channels
	for i := 1; i <= 3; i++ {
		respN, _ := json.Marshal(structs.FileUploadMessageResponse{
			ChunkNum: i, ChunkData: chunk, TotalChunks: 3,
		})
		fileTransferResp <- respN

		// Drain messages until we get the chunk data on receivedChunks
		drainTimeout := time.After(3 * time.Second)
	drainLoop:
		for {
			select {
			case resp := <-task.Job.SendResponses:
				if strings.Contains(resp.UserOutput, "Fetching file") {
					gotFetchStatus = true
				}
				// Could also be a chunk request for next iteration or status update
			case <-receivedChunks:
				break drainLoop
			case <-drainTimeout:
				t.Fatalf("Timed out on chunk %d", i)
			}
		}
	}

	if !gotFetchStatus {
		t.Error("Expected 'Fetching file' status update with SendUserStatusUpdates=true")
	}

	// Done signal
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty done signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for done signal")
	}
}

// Test: Bad JSON in mid-transfer chunk
func TestGetFile_BadJSONMidTransfer(t *testing.T) {
	task := newTestTask("task-get-midjson")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "midjson-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send valid first chunk (2 total)
	chunk := base64.StdEncoding.EncodeToString([]byte("first"))
	resp1, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: chunk, TotalChunks: 2,
	})
	fileTransferResp <- resp1

	// Receive chunk 1 data
	select {
	case <-receivedChunks:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Receive request for chunk 2
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send bad JSON for chunk 2
	fileTransferResp <- json.RawMessage(`{broken`)

	// Should get error
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Failed to parse") {
			t.Errorf("Expected parse error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Should signal done
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty error signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// Test: Invalid base64 in mid-transfer chunk
func TestGetFile_InvalidBase64MidTransfer(t *testing.T) {
	task := newTestTask("task-get-midb64")
	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "midb64-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send valid first chunk
	chunk := base64.StdEncoding.EncodeToString([]byte("first"))
	resp1, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: chunk, TotalChunks: 2,
	})
	fileTransferResp <- resp1

	// Receive chunk 1
	select {
	case <-receivedChunks:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Receive request for chunk 2
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send chunk 2 with invalid base64
	resp2, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 2, ChunkData: "!!invalid!!", TotalChunks: 2,
	})
	fileTransferResp <- resp2

	// Should get error
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Failed to parse") {
			t.Errorf("Expected parse error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Should signal done
	select {
	case data := <-receivedChunks:
		if len(data) != 0 {
			t.Errorf("Expected empty error signal, got %d bytes", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}
}

// =============================================================================
// listenForSendFileToMythicMessages / listenForGetFromMythicMessages Tests
// =============================================================================

// Test: listenForSendFileToMythicMessages sets up tracking UUID and channels
func TestListenForSendFile_SetsUpTracking(t *testing.T) {
	// Reset and re-initialize to start fresh listeners
	initOnce = sync.Once{}
	Initialize()

	task := newTestTask("task-listen-send")
	finished := make(chan int, 1)

	// Send a no-data-no-file struct through the channel (will error immediately)
	SendToMythicChannel <- structs.SendFileToMythicStruct{
		Task:             task,
		FinishedTransfer: finished,
	}

	// Should get error response
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "No data and no file") {
			t.Errorf("Expected error, got: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out — listener not running?")
	}

	<-finished
}

// Test: listenForGetFromMythicMessages sets up tracking
func TestListenForGetFile_SetsUpTracking(t *testing.T) {
	initOnce = sync.Once{}
	Initialize()

	task := newTestTask("task-listen-get")
	receivedChunks := make(chan []byte, 10)
	fileTransferResp := make(chan json.RawMessage, 10)

	GetFromMythicChannel <- structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "listen-test-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	// Should get upload request
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Upload == nil {
			t.Fatal("Expected Upload in response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out — listener not running?")
	}

	// Send a valid response to let it finish
	chunk := base64.StdEncoding.EncodeToString([]byte("data"))
	chunkResp, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: chunk, TotalChunks: 1,
	})

	// The listener creates its own FileTransferResponse channel,
	// but we need the one it actually passes. Let's check if the task's
	// FileTransfers map was populated
	time.Sleep(100 * time.Millisecond) // Let goroutine run

	task.Job.FileTransfersMu.RLock()
	var trackingCh chan json.RawMessage
	for _, ch := range task.Job.FileTransfers {
		trackingCh = ch
		break
	}
	task.Job.FileTransfersMu.RUnlock()

	if trackingCh != nil {
		trackingCh <- chunkResp
		// Receive chunk
		select {
		case <-receivedChunks:
		case <-time.After(2 * time.Second):
			t.Fatal("Timed out")
		}
		// Done signal
		select {
		case data := <-receivedChunks:
			if len(data) != 0 {
				t.Errorf("Expected empty done signal")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Timed out")
		}
	}
}

// =============================================================================
// waitForFileResponse Direct Unit Tests
// =============================================================================

// Test: waitForFileResponse returns data when available immediately
func TestWaitForFileResponse_ImmediateData(t *testing.T) {
	ch := make(chan json.RawMessage, 1)
	expected := json.RawMessage(`{"file_id":"abc"}`)
	ch <- expected

	data, ok := waitForFileResponse(ch, 1*time.Second)
	if !ok {
		t.Fatal("Expected ok=true, got false")
	}
	if string(data) != string(expected) {
		t.Errorf("Expected %q, got %q", expected, data)
	}
}

// Test: waitForFileResponse times out when no data
func TestWaitForFileResponse_Timeout(t *testing.T) {
	ch := make(chan json.RawMessage)

	start := time.Now()
	data, ok := waitForFileResponse(ch, 50*time.Millisecond)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("Expected ok=false on timeout, got true")
	}
	if data != nil {
		t.Errorf("Expected nil data on timeout, got: %v", data)
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Returned too quickly: %v", elapsed)
	}
}

// Test: waitForFileResponse with data arriving just before timeout
func TestWaitForFileResponse_DataBeforeTimeout(t *testing.T) {
	ch := make(chan json.RawMessage, 1)

	go func() {
		time.Sleep(20 * time.Millisecond)
		ch <- json.RawMessage(`{"status":"ok"}`)
	}()

	data, ok := waitForFileResponse(ch, 500*time.Millisecond)
	if !ok {
		t.Fatal("Expected ok=true when data arrives before timeout")
	}
	if string(data) != `{"status":"ok"}` {
		t.Errorf("Unexpected data: %q", data)
	}
}

// =============================================================================
// sendFileMessagesToMythic Error Path Tests
// =============================================================================

// Test: File.Stat() error when using os.File
func TestSendFile_FileStatError(t *testing.T) {
	task := newTestTask("task-stat-err")
	finished := make(chan int, 1)

	// Create and close a temp file so Stat() will fail
	tmpFile, err := os.CreateTemp("", "stat-err-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	os.Remove(tmpFile.Name())

	// Reopen the removed file's descriptor — Stat() should fail
	// Actually, we need to use the closed/removed file object
	msg := structs.SendFileToMythicStruct{
		Task:             task,
		File:             tmpFile, // closed file
		FinishedTransfer: finished,
	}

	go sendFileMessagesToMythic(msg)

	// Should get error about file size
	select {
	case resp := <-task.Job.SendResponses:
		if !strings.Contains(resp.UserOutput, "Error getting file size") {
			t.Errorf("Expected file stat error, got: %s", resp.UserOutput)
		}
		if !resp.Completed {
			t.Error("Expected Completed=true on stat error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for stat error response")
	}

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished signal")
	}
}

// Test: ShouldStop during chunk transfer
func TestSendFile_ShouldStopDuringTransfer(t *testing.T) {
	// Use NewTask to get proper stopped field
	realTask := structs.NewTask("task-shouldstop", "download", "")
	stop := 0
	realTask.Job = &structs.Job{
		Stop:          &stop,
		SendResponses: make(chan structs.Response, 100),
		FileTransfers: make(map[string]chan json.RawMessage),
	}
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	// Create data for 3 chunks so we have multiple loop iterations
	testData := make([]byte, FILE_CHUNK_SIZE*3)
	msg := structs.SendFileToMythicStruct{
		Task:                 &realTask,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-realTask.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "stop-file"})
	fileTransferResp <- fileIDResp

	// Receive file_id output
	select {
	case <-realTask.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Receive and ack chunk 1 (ShouldStop not yet set)
	select {
	case <-realTask.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk 1")
	}

	// Ack chunk 1 as success
	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})
	fileTransferResp <- successResp

	// Now set stop before chunk 2 processing
	realTask.SetStop()

	// The transfer should finish due to ShouldStop check at top of chunk loop
	select {
	case <-finished:
		// Good — transfer stopped
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out — ShouldStop did not terminate transfer")
	}
}

// Test: Closed channel during file_id exchange (simulates connection loss)
func TestSendFile_ClosedChannelDuringFileID(t *testing.T) {
	task := newTestTask("task-closed-ch")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 1)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for announcement")
	}

	// Close the channel — reading returns nil RawMessage immediately
	// which causes json.Unmarshal to fail on nil input
	close(fileTransferResp)

	// Should get an unmarshal error (nil input to json.Unmarshal)
	select {
	case resp := <-task.Job.SendResponses:
		if resp.UserOutput == "" {
			t.Error("Expected error output")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for error")
	}

	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for finished")
	}
}

// Test: file_id in response is not a string (type assertion failure)
func TestSendFile_FileIDNotString(t *testing.T) {
	task := newTestTask("task-fileid-type")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	testData := []byte("test")
	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		Data:                 &testData,
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Receive initial announcement
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send file_id as a number instead of string
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": 12345})
	fileTransferResp <- fileIDResp

	// Receive file_id output (the info message)
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Now it will try to read a chunk and do the type assertion on file_id
	// The chunk is sent, then file_id.(string) assertion should fail
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download != nil {
			// This is the chunk data — ack it, then the type assertion will be attempted
			// after the chunk send, during the loop iteration
			// Actually, looking at the code more carefully: file_id type assertion happens
			// inside the chunk loop at line 168. So the chunk data is already being sent,
			// then when constructing fileDownloadData.FileID, the assertion fails.

			// Wait for the error
			select {
			case errResp := <-task.Job.SendResponses:
				if !strings.Contains(errResp.UserOutput, "file_id not found or not a string") {
					t.Errorf("Expected file_id type error, got: %s", errResp.UserOutput)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Timed out waiting for type assertion error")
			}
		} else if strings.Contains(resp.UserOutput, "file_id not found or not a string") {
			// Got the error directly
		} else {
			t.Errorf("Unexpected response: %s", resp.UserOutput)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished")
	}
}

// =============================================================================
// sendUploadFileMessagesToMythic Error Path Tests
// =============================================================================

// Test: ShouldStop during multi-chunk download from Mythic
func TestGetFile_ShouldStopDuringTransfer(t *testing.T) {
	realTask := structs.NewTask("task-get-stop", "upload", "")
	stop := 0
	realTask.Job = &structs.Job{
		Stop:          &stop,
		SendResponses: make(chan structs.Response, 100),
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	fileTransferResp := make(chan json.RawMessage, 10)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 &realTask,
		FileID:               "stop-dl-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-realTask.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send first chunk (3 total) to enter the multi-chunk loop
	chunk1 := base64.StdEncoding.EncodeToString([]byte("data1"))
	resp1, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 1, ChunkData: chunk1, TotalChunks: 3,
	})
	fileTransferResp <- resp1

	// Receive chunk 1 data
	select {
	case <-receivedChunks:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out receiving chunk 1")
	}

	// Set stop before chunk 2
	realTask.SetStop()

	// Receive request for chunk 2 (sent before stop check)
	select {
	case <-realTask.Job.SendResponses:
		// May or may not get this depending on timing
	case data := <-receivedChunks:
		// Got the empty done signal — transfer stopped
		if len(data) != 0 {
			t.Errorf("Expected empty stop signal, got %d bytes", len(data))
		}
		return
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out — ShouldStop did not terminate download")
	}

	// If we got the chunk 2 request, the stop should take effect on next iteration
	// Send chunk 2 to let it proceed
	chunk2 := base64.StdEncoding.EncodeToString([]byte("data2"))
	resp2, _ := json.Marshal(structs.FileUploadMessageResponse{
		ChunkNum: 2, ChunkData: chunk2, TotalChunks: 3,
	})
	fileTransferResp <- resp2

	// Drain until we get empty signal
	timeout := time.After(3 * time.Second)
	for {
		select {
		case data := <-receivedChunks:
			if len(data) == 0 {
				return // Success — transfer stopped
			}
		case <-timeout:
			t.Fatal("Timed out waiting for stop signal")
		}
	}
}

// Test: Timeout waiting for first chunk from Mythic (closed channel simulates)
func TestGetFile_TimeoutOnFirstChunk(t *testing.T) {
	task := newTestTask("task-get-timeout")
	fileTransferResp := make(chan json.RawMessage)
	receivedChunks := make(chan []byte, 10)

	msg := structs.GetFileFromMythicStruct{
		Task:                 task,
		FileID:               "timeout-file",
		ReceivedChunkChannel: receivedChunks,
		FileTransferResponse: fileTransferResp,
	}

	go sendUploadFileMessagesToMythic(msg)

	// Receive initial request
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Close the channel to simulate the timeout path
	// (reading from closed channel returns zero value immediately)
	close(fileTransferResp)

	// Should get either an error response or an empty chunk
	timeout := time.After(3 * time.Second)
	gotError := false
	for !gotError {
		select {
		case resp := <-task.Job.SendResponses:
			if strings.Contains(resp.UserOutput, "Failed to parse") || strings.Contains(resp.UserOutput, "timed out") {
				gotError = true
			}
		case data := <-receivedChunks:
			if len(data) == 0 {
				gotError = true // Transfer ended
			}
		case <-timeout:
			t.Fatal("Timed out waiting for error handling")
		}
	}
}

// Test: Send file with os.File that has been seeked to end
func TestSendFile_FileSeekAndRead(t *testing.T) {
	task := newTestTask("task-seek")
	finished := make(chan int, 1)
	fileTransferResp := make(chan json.RawMessage, 10)

	// Create a temp file with multi-chunk content
	tmpFile, err := os.CreateTemp("", "seek-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write exactly 2 chunks worth of data
	content := make([]byte, FILE_CHUNK_SIZE+100)
	for i := range content {
		content[i] = byte(i % 256)
	}
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Seek to end (simulate a file that was just written)
	tmpFile.Seek(0, 2) // seek to end

	msg := structs.SendFileToMythicStruct{
		Task:                 task,
		File:                 tmpFile,
		FullPath:             tmpFile.Name(),
		FinishedTransfer:     finished,
		FileTransferResponse: fileTransferResp,
	}

	go sendFileMessagesToMythic(msg)

	// Initial announcement
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.TotalChunks != 2 {
			t.Errorf("Expected 2 chunks, got %d", resp.Download.TotalChunks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	// Send file_id
	fileIDResp, _ := json.Marshal(map[string]interface{}{"file_id": "seek-file"})
	fileTransferResp <- fileIDResp

	// file_id output
	select {
	case <-task.Job.SendResponses:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out")
	}

	successResp, _ := json.Marshal(map[string]interface{}{"status": "success"})

	// Chunk 1
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.ChunkNum != 1 {
			t.Errorf("Expected chunk 1, got %d", resp.Download.ChunkNum)
		}
		decoded, _ := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if len(decoded) != FILE_CHUNK_SIZE {
			t.Errorf("Chunk 1 should be %d bytes, got %d", FILE_CHUNK_SIZE, len(decoded))
		}
		// Verify content matches (the file was seeked to end, but sendFile should seek back)
		for i := 0; i < len(decoded); i++ {
			if decoded[i] != byte(i%256) {
				t.Errorf("Chunk 1 data mismatch at byte %d: got %d, want %d", i, decoded[i], byte(i%256))
				break
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk 1")
	}

	fileTransferResp <- successResp

	// Chunk 2
	select {
	case resp := <-task.Job.SendResponses:
		if resp.Download.ChunkNum != 2 {
			t.Errorf("Expected chunk 2, got %d", resp.Download.ChunkNum)
		}
		decoded, _ := base64.StdEncoding.DecodeString(resp.Download.ChunkData)
		if len(decoded) != 100 {
			t.Errorf("Chunk 2 should be 100 bytes, got %d", len(decoded))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for chunk 2")
	}

	fileTransferResp <- successResp

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for finished")
	}

	tmpFile.Close()
}
