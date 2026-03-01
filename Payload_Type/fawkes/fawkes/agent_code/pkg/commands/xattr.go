//go:build !windows
// +build !windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// XattrCommand manages extended file attributes (Unix complement to Windows ADS)
type XattrCommand struct{}

func (c *XattrCommand) Name() string { return "xattr" }
func (c *XattrCommand) Description() string {
	return "Manage extended file attributes — list, get, set, delete. Unix complement to Windows ADS for data hiding (T1564.004)"
}

type xattrArgs struct {
	Action string `json:"action"` // list, get, set, delete
	Path   string `json:"path"`   // Target file path
	Name   string `json:"name"`   // Attribute name (e.g., "user.secret")
	Value  string `json:"value"`  // Value to set
	Hex    bool   `json:"hex"`    // Write/read as hex-encoded binary
}

func (c *XattrCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <list|get|set|delete> -path <file> [-name <attr>] [-value <data>] [-hex true]",
			Status:    "error",
			Completed: true,
		}
	}

	var args xattrArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Parse "action path [name] [value]"
		parts := strings.Fields(task.Params)
		if len(parts) >= 2 {
			args.Action = parts[0]
			args.Path = parts[1]
			if len(parts) >= 3 {
				args.Name = parts[2]
			}
			if len(parts) >= 4 {
				args.Value = strings.Join(parts[3:], " ")
			}
		} else if len(parts) == 1 {
			args.Path = parts[0]
			args.Action = "list"
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Verify file exists
	if _, err := os.Stat(args.Path); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "list", "":
		return xattrList(args)
	case "get":
		return xattrGet(args)
	case "set":
		return xattrSet(args)
	case "delete":
		return xattrDelete(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action '%s'. Use list, get, set, or delete.", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func xattrList(args xattrArgs) structs.CommandResult {
	attrs, err := listXattr(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing xattrs: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(attrs) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("[*] %s: no extended attributes", args.Path),
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s: %d extended attribute(s)\n\n", args.Path, len(attrs)))
	for _, attr := range attrs {
		data, err := getXattr(args.Path, attr)
		size := 0
		if err == nil {
			size = len(data)
		}
		sb.WriteString(fmt.Sprintf("  %-40s  %d bytes\n", attr, size))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func xattrGet(args xattrArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for get action",
			Status:    "error",
			Completed: true,
		}
	}

	data, err := getXattr(args.Path, args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading xattr '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s : %s (%d bytes)\n", args.Path, args.Name, len(data)))
	if args.Hex {
		sb.WriteString(hex.Dump(data))
	} else {
		sb.WriteString(string(data))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func xattrSet(args xattrArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for set action",
			Status:    "error",
			Completed: true,
		}
	}

	var data []byte
	if args.Hex {
		var err error
		data, err = hex.DecodeString(args.Value)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error decoding hex value: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		data = []byte(args.Value)
	}

	if err := setXattr(args.Path, args.Name, data); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting xattr '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Set xattr '%s' on %s (%d bytes)", args.Name, args.Path, len(data)),
		Status:    "success",
		Completed: true,
	}
}

func xattrDelete(args xattrArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for delete action",
			Status:    "error",
			Completed: true,
		}
	}

	if err := removeXattr(args.Path, args.Name); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing xattr '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Removed xattr '%s' from %s", args.Name, args.Path),
		Status:    "success",
		Completed: true,
	}
}
