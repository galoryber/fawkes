package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"fawkes/pkg/structs"
)

// WriteFileCommand implements the write-file command for writing content to files
type WriteFileCommand struct{}

func (c *WriteFileCommand) Name() string {
	return "write-file"
}

func (c *WriteFileCommand) Description() string {
	return "Write text or base64-decoded content to a file — create, overwrite, or append without spawning subprocesses"
}

type writeFileArgs struct {
	Action  string `json:"action"`  // write (default), deface
	Path    string `json:"path"`
	Content string `json:"content"`
	Base64  bool   `json:"base64"`
	Append  bool   `json:"append"`
	MkDirs  bool   `json:"mkdir"`
	Confirm string `json:"confirm"` // safety gate for deface ("DEFACE")
}

func (c *WriteFileCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[writeFileArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	if args.Action == "deface" {
		return writeFileDeface(args)
	}

	if args.Content == "" {
		return errorResult("Error: content is required")
	}

	// Determine the data to write
	var data []byte
	if args.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(args.Content)
		if err != nil {
			return errorf("Error decoding base64: %v", err)
		}
		data = decoded
	} else {
		data = []byte(args.Content)
	}

	// Create parent directories if requested
	if args.MkDirs {
		dir := filepath.Dir(args.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errorf("Error creating directories: %v", err)
		}
	}

	// Determine file flags
	flags := os.O_WRONLY | os.O_CREATE
	if args.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(args.Path, flags, 0644)
	if err != nil {
		return errorf("Error opening file: %v", err)
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		return errorf("Error writing file: %v", err)
	}

	action := "Wrote"
	if args.Append {
		action = "Appended"
	}

	return successf("[+] %s %d bytes to %s", action, n, args.Path)
}

// writeFileDeface replaces a file's content with a defacement message (T1491).
// Targets web server files (index.html, etc.) for purple team impact simulation.
// Safety gate: -confirm DEFACE required.
func writeFileDeface(args writeFileArgs) structs.CommandResult {
	if args.Confirm != "DEFACE" {
		return errorResult("Error: deface requires -confirm DEFACE (safety gate for web defacement)")
	}

	content := args.Content
	if content == "" {
		// Default defacement HTML if no custom content provided
		content = `<!DOCTYPE html>
<html><head><title>DEFACED</title></head>
<body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:20%">
<h1>THIS SITE HAS BEEN DEFACED</h1>
<p>Purple team exercise — authorized security assessment</p>
</body></html>`
	}

	// Back up original file content before overwriting
	var backupInfo string
	origInfo, err := os.Stat(args.Path)
	if err == nil {
		backupInfo = fmt.Sprintf(" (original: %s)", formatFileSize(origInfo.Size()))
	}

	f, err := os.OpenFile(args.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errorf("Error opening %s for defacement: %v", args.Path, err)
	}
	defer f.Close()

	n, err := f.Write([]byte(content))
	if err != nil {
		return errorf("Error writing defacement: %v", err)
	}

	return successf("[+] Defaced: %s (%d bytes written%s)", args.Path, n, backupInfo)
}
