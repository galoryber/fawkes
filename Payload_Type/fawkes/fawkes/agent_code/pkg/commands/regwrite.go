//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// RegWriteCommand implements the reg-write command
type RegWriteCommand struct{}

// Name returns the command name
func (c *RegWriteCommand) Name() string {
	return "reg-write"
}

// Description returns the command description
func (c *RegWriteCommand) Description() string {
	return "Write a value to the Windows Registry"
}

// RegWriteParams represents the JSON parameters
type RegWriteParams struct {
	Hive    string `json:"hive"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Data    string `json:"data"`
	RegType string `json:"reg_type"`
}

// Execute implements the Command interface
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

	// Open or create the key
	key, _, err := registry.CreateKey(hiveKey, params.Path, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening/creating key %s\\%s: %v", params.Hive, params.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	// Write the value based on type
	switch strings.ToUpper(params.RegType) {
	case "REG_SZ":
		err = key.SetStringValue(params.Name, params.Data)
	case "REG_EXPAND_SZ":
		err = key.SetExpandStringValue(params.Name, params.Data)
	case "REG_DWORD":
		val, parseErr := strconv.ParseUint(params.Data, 10, 32)
		if parseErr != nil {
			// Try hex
			val, parseErr = strconv.ParseUint(strings.TrimPrefix(params.Data, "0x"), 16, 32)
			if parseErr != nil {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Error: invalid DWORD value '%s' (use decimal or 0x hex)", params.Data),
					Status:    "error",
					Completed: true,
				}
			}
		}
		err = key.SetDWordValue(params.Name, uint32(val))
	case "REG_QWORD":
		val, parseErr := strconv.ParseUint(params.Data, 10, 64)
		if parseErr != nil {
			val, parseErr = strconv.ParseUint(strings.TrimPrefix(params.Data, "0x"), 16, 64)
			if parseErr != nil {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Error: invalid QWORD value '%s' (use decimal or 0x hex)", params.Data),
					Status:    "error",
					Completed: true,
				}
			}
		}
		err = key.SetQWordValue(params.Name, val)
	case "REG_BINARY":
		binData, parseErr := hex.DecodeString(strings.TrimPrefix(params.Data, "0x"))
		if parseErr != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: invalid binary hex data '%s': %v", params.Data, parseErr),
				Status:    "error",
				Completed: true,
			}
		}
		err = key.SetBinaryValue(params.Name, binData)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unsupported registry type '%s' (use REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, or REG_BINARY)", params.RegType),
			Status:    "error",
			Completed: true,
		}
	}

	if err != nil {
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
