package commands

import (
	"encoding/base64"
	"encoding/json"
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
	Path    string `json:"path"`
	Content string `json:"content"`
	Base64  bool   `json:"base64"`
	Append  bool   `json:"append"`
	MkDirs  bool   `json:"mkdir"`
}

func (c *WriteFileCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args writeFileArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Content == "" {
		return structs.CommandResult{
			Output:    "Error: content is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Determine the data to write
	var data []byte
	if args.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(args.Content)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error decoding base64: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		data = decoded
	} else {
		data = []byte(args.Content)
	}

	// Create parent directories if requested
	if args.MkDirs {
		dir := filepath.Dir(args.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating directories: %v", err),
				Status:    "error",
				Completed: true,
			}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	action := "Wrote"
	if args.Append {
		action = "Appended"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] %s %d bytes to %s", action, n, args.Path),
		Status:    "success",
		Completed: true,
	}
}
