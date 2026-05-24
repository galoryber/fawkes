package commands

import (
	"encoding/json"
	"fawkes/pkg/files"
	"fawkes/pkg/structs"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// mockJob creates a minimal Job suitable for upload command tests.
// The returned goroutine (and wg) allows callers to inspect the GetFileFromMythic
// request before signalling completion.
func mockUploadJob(t *testing.T) (*structs.Job, func(fn func(req structs.GetFileFromMythicStruct)), *sync.WaitGroup) {
	t.Helper()
	job := &structs.Job{
		Stop:              new(int),
		SendResponses:     make(chan structs.Response, 20),
		GetFileFromMythic: make(chan structs.GetFileFromMythicStruct, 1),
		FileTransfers:     make(map[string]chan json.RawMessage),
	}
	wg := &sync.WaitGroup{}

	// Start a goroutine that handles a single GetFileFromMythic request
	handle := func(fn func(req structs.GetFileFromMythicStruct)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := <-job.GetFileFromMythic
			if fn != nil {
				fn(req)
			}
			// Signal transfer complete immediately (empty slice = done)
			req.ReceivedChunkChannel <- make([]byte, 0)
		}()
	}

	return job, handle, wg
}

// makeUploadTask creates a Task with the given file_id, remote_path, and optional overwrite
func makeUploadTask(fileID, remotePath string, overwrite bool) structs.Task {
	args, _ := json.Marshal(UploadArgs{
		FileID:     fileID,
		RemotePath: remotePath,
		Overwrite:  overwrite,
	})
	return structs.Task{Params: string(args)}
}

// TestUploadResume_MatchingState verifies that when a TransferState with matching
// FileID exists, the upload resumes (StartChunk > 1, file not truncated).
func TestUploadResume_MatchingState(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "partial.bin")

	// Pre-create a partial file (simulating a stopped transfer at chunk 3)
	partialContent := []byte("first-three-chunks-worth-of-data")
	if err := os.WriteFile(destPath, partialContent, 0700); err != nil {
		t.Fatal(err)
	}

	fileID := "mythic-file-abc"
	files.SaveTransferState(&files.TransferState{
		FileID:    fileID,
		FullPath:  destPath,
		Direction: files.TransferUpload,
		LastChunk: 3,
		TotalChunks: 10,
	})
	defer files.ClearTransferState(destPath)

	job, handle, wg := mockUploadJob(t)
	var capturedStartChunk int
	handle(func(req structs.GetFileFromMythicStruct) {
		capturedStartChunk = req.StartChunk
	})

	task := makeUploadTask(fileID, destPath, false)
	task.Job = job

	result := (&UploadCommand{}).Execute(task)
	wg.Wait()

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	// StartChunk should be lastChunk + 1 = 4
	if capturedStartChunk != 4 {
		t.Errorf("expected StartChunk=4 (resume from chunk 4), got %d", capturedStartChunk)
	}

	// File content should not be truncated (partial content still there)
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(partialContent) {
		t.Errorf("partial content was lost: expected %q, got %q", partialContent, string(data))
	}

	// Output should mention resume
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}

// TestUploadResume_FileIDMismatch verifies that when the saved TransferState has a
// different FileID, the upload starts fresh (StartChunk=0) and truncates the file.
func TestUploadResume_FileIDMismatch(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "file.bin")

	partialContent := []byte("stale-data-from-different-file")
	if err := os.WriteFile(destPath, partialContent, 0700); err != nil {
		t.Fatal(err)
	}

	// Save state for a different FileID
	files.SaveTransferState(&files.TransferState{
		FileID:    "old-file-id",
		FullPath:  destPath,
		Direction: files.TransferUpload,
		LastChunk: 5,
	})
	defer files.ClearTransferState(destPath)

	job, handle, wg := mockUploadJob(t)
	var capturedStartChunk int
	handle(func(req structs.GetFileFromMythicStruct) {
		capturedStartChunk = req.StartChunk
	})

	// New upload with a DIFFERENT FileID and overwrite=true
	task := makeUploadTask("new-file-id", destPath, true)
	task.Job = job

	result := (&UploadCommand{}).Execute(task)
	wg.Wait()

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	// StartChunk should be 1 (fresh start — no resume)
	if capturedStartChunk != 0 && capturedStartChunk != 1 {
		t.Errorf("expected StartChunk=0 or 1 (fresh start), got %d", capturedStartChunk)
	}

	// File should be truncated (stale data gone)
	data, _ := os.ReadFile(destPath)
	if string(data) == string(partialContent) {
		t.Error("file should have been truncated for fresh start, but stale content remains")
	}
}

// TestUploadResume_NoExistingState verifies normal upload when no TransferState exists.
func TestUploadResume_NoExistingState(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "fresh.bin")

	// Ensure no state exists
	files.ClearTransferState(destPath)

	job, handle, wg := mockUploadJob(t)
	var capturedStartChunk int
	handle(func(req structs.GetFileFromMythicStruct) {
		capturedStartChunk = req.StartChunk
	})

	task := makeUploadTask("file-id-123", destPath, false)
	task.Job = job

	result := (&UploadCommand{}).Execute(task)
	wg.Wait()

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	// No resume: StartChunk should be 0 or 1
	if capturedStartChunk != 0 && capturedStartChunk != 1 {
		t.Errorf("expected StartChunk=0/1 for fresh upload, got %d", capturedStartChunk)
	}
}

// TestUploadResume_DecompressSkipsResume verifies that decompress mode does NOT use
// resume state (writes to a temp file, so resume logic is skipped).
func TestUploadResume_DecompressSkipsResume(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "decompressed.txt")

	// Save a seemingly valid resume state
	files.SaveTransferState(&files.TransferState{
		FileID:    "gz-file-id",
		FullPath:  destPath,
		Direction: files.TransferUpload,
		LastChunk: 2,
	})
	defer files.ClearTransferState(destPath)

	job, handle, wg := mockUploadJob(t)
	var capturedStartChunk int
	handle(func(req structs.GetFileFromMythicStruct) {
		capturedStartChunk = req.StartChunk
	})

	args, _ := json.Marshal(UploadArgs{
		FileID:     "gz-file-id",
		RemotePath: destPath,
		Decompress: true,
	})
	task := structs.Task{Params: string(args)}
	task.Job = job

	// This will fail during decompression (empty transfer = not a valid gzip),
	// but that's fine — we just want to check StartChunk.
	(&UploadCommand{}).Execute(task)
	wg.Wait()

	// Even though FileID matches, decompress mode should NOT resume
	if capturedStartChunk != 0 && capturedStartChunk != 1 {
		t.Errorf("decompress mode should not resume (StartChunk should be 0/1), got %d", capturedStartChunk)
	}
}

// TestUploadResume_ExistingFileNoOverwriteNoState verifies that the "file exists"
// error is returned when there's no resume state and overwrite=false.
func TestUploadResume_ExistingFileNoOverwriteNoState(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "existing.txt")
	os.WriteFile(destPath, []byte("original"), 0644)

	files.ClearTransferState(destPath)

	task := makeUploadTask("some-file-id", destPath, false)
	result := (&UploadCommand{}).Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error for existing file without overwrite, got %s", result.Status)
	}
}

// TestUploadResume_StateCleared verifies that after a successful upload, the
// TransferState is cleared (so a subsequent upload starts fresh).
func TestUploadResume_StateCleared(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "cleartest.bin")
	fileID := "clear-test-id"

	// No existing state
	files.ClearTransferState(destPath)

	job, handle, wg := mockUploadJob(t)
	handle(nil) // no capture needed

	task := makeUploadTask(fileID, destPath, false)
	task.Job = job

	result := (&UploadCommand{}).Execute(task)
	wg.Wait()

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	// TransferState should be cleared after successful completion
	state := files.GetTransferState(destPath, files.TransferUpload)
	if state != nil {
		t.Error("TransferState should be cleared after successful upload")
	}
}
