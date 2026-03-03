//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// RegReadCommand implements the reg-read command
type RegReadCommand struct{}

func (c *RegReadCommand) Name() string        { return "reg-read" }
func (c *RegReadCommand) Description() string { return "Read a value from the Windows Registry" }

// RegReadParams represents the JSON parameters
type RegReadParams struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
	Name string `json:"name"`
}

func (c *RegReadCommand) Execute(task structs.Task) structs.CommandResult {
	var params RegReadParams
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

	key, err := registry.OpenKey(hiveKey, params.Path, registry.READ)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening key %s\\%s: %v", params.Hive, params.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	if params.Name != "" {
		output, err := readValue(key, params.Name)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading value '%s': %v", params.Name, err),
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

	output, err := enumerateValues(key, params.Hive, params.Path)
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
