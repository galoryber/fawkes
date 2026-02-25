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

type RegDeleteCommand struct{}

func (c *RegDeleteCommand) Name() string {
	return "reg-delete"
}

func (c *RegDeleteCommand) Description() string {
	return "Delete a registry key or value from the Windows Registry"
}

type regDeleteArgs struct {
	Hive      string `json:"hive"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Recursive string `json:"recursive"`
}

func (c *RegDeleteCommand) Execute(task structs.Task) structs.CommandResult {
	var args regDeleteArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (hive, path)",
			Status:    "error",
			Completed: true,
		}
	}

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

	hiveKey, err := parseHive(args.Hive)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Name != "" {
		// Delete a specific value
		return regDeleteValue(hiveKey, args)
	}

	// Delete the key itself
	recursive := strings.ToLower(args.Recursive) == "true" || args.Recursive == "1"
	return regDeleteKey(hiveKey, args, recursive)
}

func regDeleteValue(hiveKey registry.Key, args regDeleteArgs) structs.CommandResult {
	key, err := registry.OpenKey(hiveKey, args.Path, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	err = key.DeleteValue(args.Name)
	if err != nil {
		displayName := args.Name
		if displayName == "" {
			displayName = "(Default)"
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting value '%s': %v", displayName, err),
			Status:    "error",
			Completed: true,
		}
	}

	displayName := args.Name
	if displayName == "" {
		displayName = "(Default)"
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted value: %s\\%s\\%s", args.Hive, args.Path, displayName),
		Status:    "success",
		Completed: true,
	}
}

func regDeleteKey(hiveKey registry.Key, args regDeleteArgs, recursive bool) structs.CommandResult {
	if recursive {
		return regDeleteKeyRecursive(hiveKey, args)
	}

	// Non-recursive: delete the leaf key only
	err := registry.DeleteKey(hiveKey, args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting key %s\\%s: %v (if key has subkeys, use -recursive true)", args.Hive, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted key: %s\\%s", args.Hive, args.Path),
		Status:    "success",
		Completed: true,
	}
}

func regDeleteKeyRecursive(hiveKey registry.Key, args regDeleteArgs) structs.CommandResult {
	var sb strings.Builder
	count, err := deleteSubKeysRecursive(hiveKey, args.Path, &sb)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Error during recursive delete: %v\n", err))
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString(fmt.Sprintf("\nDeleted %s\\%s (%d keys removed)", args.Hive, args.Path, count))
	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func deleteSubKeysRecursive(hiveKey registry.Key, path string, sb *strings.Builder) (int, error) {
	count := 0

	// Open the key to enumerate subkeys
	key, err := registry.OpenKey(hiveKey, path, registry.READ)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %v", path, err)
	}

	subkeys, err := key.ReadSubKeyNames(-1)
	key.Close()
	if err != nil {
		return 0, fmt.Errorf("cannot enumerate subkeys of %s: %v", path, err)
	}

	// Delete children first (deepest first)
	for _, sk := range subkeys {
		childPath := path + `\` + sk
		n, err := deleteSubKeysRecursive(hiveKey, childPath, sb)
		if err != nil {
			return count, err
		}
		count += n
	}

	// Now delete this leaf key
	err = registry.DeleteKey(hiveKey, path)
	if err != nil {
		return count, fmt.Errorf("cannot delete %s: %v", path, err)
	}
	count++
	sb.WriteString(fmt.Sprintf("  Deleted: %s\n", path))
	return count, nil
}
