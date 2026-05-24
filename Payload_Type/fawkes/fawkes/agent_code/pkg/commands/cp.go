package commands

import (
	"encoding/json"
	"io"
	"os"

	"fawkes/pkg/structs"
)

// CpCommand implements the cp command
type CpCommand struct{}

// Name returns the command name
func (c *CpCommand) Name() string {
	return "cp"
}

// Description returns the command description
func (c *CpCommand) Description() string {
	return "Copy file - copies a file from source to destination"
}

// Execute executes the cp command
func (c *CpCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}

	// Check if parameters are provided
	if task.Params == "" {
		return errorResult("Error: No parameters specified. Usage: cp <source> <destination>")
	}

	// Try to parse as JSON
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v. Usage: cp <source> <destination>", err)
	}

	// Strip surrounding quotes in case the user wrapped paths (e.g. "C:\Program Data\file.txt")
	args.Source = stripPathQuotes(args.Source)
	args.Destination = stripPathQuotes(args.Destination)

	// Validate parameters
	if args.Source == "" || args.Destination == "" {
		return errorResult("Error: Both source and destination must be specified")
	}

	// Open source file
	sourceFile, err := os.Open(args.Source)
	if err != nil {
		if os.IsNotExist(err) {
			return errorf("Error: source file not found: %s", args.Source)
		}
		if os.IsPermission(err) {
			return errorf("Error: access denied to source file %s — check privileges", args.Source)
		}
		return errorf("Error: cannot open source file %s", args.Source)
	}
	defer sourceFile.Close()

	// Get source file info
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return errorf("Error: cannot read source file metadata for %s", args.Source)
	}

	if sourceInfo.IsDir() {
		return errorf("Error: %s is a directory, not a file", args.Source)
	}

	// Create destination file
	destFile, err := os.Create(args.Destination)
	if err != nil {
		if os.IsPermission(err) {
			return errorf("Error: access denied writing to %s — check privileges", args.Destination)
		}
		if os.IsNotExist(err) {
			return errorf("Error: destination directory does not exist for %s", args.Destination)
		}
		return errorf("Error: cannot create destination file %s", args.Destination)
	}
	defer destFile.Close() // Safety net for panics; explicit Close below catches flush errors
	// Copy the file contents
	bytesCopied, err := io.Copy(destFile, sourceFile)
	if err != nil {
		destFile.Close()
		return errorf("Error: write failed during copy (disk full or I/O error)")
	}

	// Close destination file explicitly to flush writes and catch errors
	if err := destFile.Close(); err != nil {
		return errorf("Error: failed to finalize %s (disk full or I/O error)", args.Destination)
	}

	// Set permissions on destination file to match source
	if err := os.Chmod(args.Destination, sourceInfo.Mode()); err != nil {
		return successf("File copied (%d bytes) but failed to set permissions: %v", bytesCopied, err)
	}

	return successf("Successfully copied %d bytes from %s to %s", bytesCopied, args.Source, args.Destination)
}
