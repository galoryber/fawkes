package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// TouchCommand implements the touch command for creating files and updating timestamps
type TouchCommand struct{}

func (c *TouchCommand) Name() string {
	return "touch"
}

func (c *TouchCommand) Description() string {
	return "Create empty files or update file timestamps — no subprocess spawned"
}

type touchArgs struct {
	Path  string `json:"path"`
	MkDir bool   `json:"mkdir"` // create parent directories
}

func (c *TouchCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args touchArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Create parent directories if requested
	if args.MkDir {
		dir := filepath.Dir(args.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating directories: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	now := time.Now()

	// Check if file exists
	_, err := os.Stat(args.Path)
	if os.IsNotExist(err) {
		// Create the file
		f, err := os.Create(args.Path)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		f.Close()

		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Created %s", args.Path),
			Status:    "success",
			Completed: true,
		}
	} else if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error accessing file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// File exists — update timestamps
	if err := os.Chtimes(args.Path, now, now); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error updating timestamps: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Updated timestamps on %s", args.Path),
		Status:    "success",
		Completed: true,
	}
}
