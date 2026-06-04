package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

type RmCommand struct{}

func (c *RmCommand) Name() string { return "rm" }

func (c *RmCommand) Description() string {
	return "Remove a file or directory. Use -secure true to overwrite file contents before deletion (T1070.004)."
}

type rmArgs struct {
	Path   string `json:"path"`
	Secure bool   `json:"secure"`
}

func (c *RmCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: No path provided")
	}

	var args rmArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = task.Params
	}

	path := args.Path
	if path == "" {
		path = task.Params
	}
	path = stripPathQuotes(path)

	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorf("Error: Path does not exist: %s", path)
		}
		if os.IsPermission(err) {
			return errorf("Error: access denied to %s — check privileges", path)
		}
		return errorf("Error: cannot access %s", path)
	}

	itemType := "file"
	if fileInfo.IsDir() {
		itemType = "directory"
	}

	if args.Secure {
		if fileInfo.IsDir() {
			count, errs := secureDeleteDir(path, 3)
			output := fmt.Sprintf("[+] Securely deleted directory: %s (%d files, 3 passes per file)", path, count)
			if len(errs) > 0 {
				output += fmt.Sprintf("\n[!] %d errors encountered", len(errs))
			}
			return successResult(output)
		}
		if err := secureDeleteFile(path, fileInfo.Size(), 3); err != nil {
			return errorf("Error securely deleting file: %v", err)
		}
		return successf("[+] Securely deleted: %s (%s, 3 passes)", path, formatFileSize(fileInfo.Size()))
	}

	err = os.RemoveAll(path)
	if err != nil {
		if os.IsPermission(err) {
			return errorf("Error: access denied — cannot remove %s %s", itemType, path)
		}
		return errorf("Error: cannot remove %s %s (in use or read-only filesystem)", itemType, path)
	}

	return successf("Successfully removed %s: %s", itemType, path)
}
