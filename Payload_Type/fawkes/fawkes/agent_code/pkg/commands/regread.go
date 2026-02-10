//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// RegReadCommand implements the reg-read command
type RegReadCommand struct{}

// Name returns the command name
func (c *RegReadCommand) Name() string {
	return "reg-read"
}

// Description returns the command description
func (c *RegReadCommand) Description() string {
	return "Read a value from the Windows Registry"
}

// RegReadParams represents the JSON parameters
type RegReadParams struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
	Name string `json:"name"`
}

// Execute implements the Command interface
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
		// Read a specific value
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

	// Enumerate all values under the key
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

// parseHive converts a hive name string to a registry.Key
func parseHive(hive string) (registry.Key, error) {
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unsupported registry hive: %s (use HKLM, HKCU, HKCR, HKU, or HKCC)", hive)
	}
}

// readValue reads a single registry value and formats it
func readValue(key registry.Key, name string) (string, error) {
	_, valType, err := key.GetValue(name, nil)
	if err != nil {
		return "", err
	}

	var output string

	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err := key.GetStringValue(name)
		if err != nil {
			return "", err
		}
		typeName := "REG_SZ"
		if valType == registry.EXPAND_SZ {
			typeName = "REG_EXPAND_SZ"
		}
		output = fmt.Sprintf("Name:  %s\nType:  %s\nValue: %s", name, typeName, val)

	case registry.DWORD:
		val, _, err := key.GetIntegerValue(name)
		if err != nil {
			return "", err
		}
		output = fmt.Sprintf("Name:  %s\nType:  REG_DWORD\nValue: %d (0x%X)", name, val, val)

	case registry.QWORD:
		val, _, err := key.GetIntegerValue(name)
		if err != nil {
			return "", err
		}
		output = fmt.Sprintf("Name:  %s\nType:  REG_QWORD\nValue: %d (0x%X)", name, val, val)

	case registry.BINARY:
		val, _, err := key.GetBinaryValue(name)
		if err != nil {
			return "", err
		}
		output = fmt.Sprintf("Name:  %s\nType:  REG_BINARY\nValue: %s (%d bytes)", name, hex.EncodeToString(val), len(val))

	case registry.MULTI_SZ:
		val, _, err := key.GetStringsValue(name)
		if err != nil {
			return "", err
		}
		output = fmt.Sprintf("Name:  %s\nType:  REG_MULTI_SZ\nValue:\n", name)
		for i, s := range val {
			output += fmt.Sprintf("  [%d] %s\n", i, s)
		}

	default:
		// Read raw bytes for unknown types
		buf := make([]byte, 1024)
		n, _, err := key.GetValue(name, buf)
		if err != nil {
			return "", err
		}
		output = fmt.Sprintf("Name:  %s\nType:  Unknown (%d)\nValue: %s", name, valType, hex.EncodeToString(buf[:n]))
	}

	return output, nil
}

// enumerateValues lists all values and subkeys under a registry key
func enumerateValues(key registry.Key, hive, path string) (string, error) {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Registry Key: %s\\%s\n\n", hive, path))

	// List subkeys
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("failed to read subkeys: %v", err)
	}
	if len(subkeys) > 0 {
		output.WriteString(fmt.Sprintf("Subkeys (%d):\n", len(subkeys)))
		for _, sk := range subkeys {
			output.WriteString(fmt.Sprintf("  %s\n", sk))
		}
		output.WriteString("\n")
	}

	// List values
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return "", fmt.Errorf("failed to read value names: %v", err)
	}

	if len(valueNames) > 0 {
		output.WriteString(fmt.Sprintf("Values (%d):\n", len(valueNames)))
		for _, vn := range valueNames {
			displayName := vn
			if displayName == "" {
				displayName = "(Default)"
			}

			_, valType, err := key.GetValue(vn, nil)
			if err != nil {
				output.WriteString(fmt.Sprintf("  %-30s  Error: %v\n", displayName, err))
				continue
			}

			typeName := registryTypeName(valType)

			switch valType {
			case registry.SZ, registry.EXPAND_SZ:
				val, _, err := key.GetStringValue(vn)
				if err != nil {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  Error: %v\n", displayName, typeName, err))
				} else {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  %s\n", displayName, typeName, val))
				}
			case registry.DWORD, registry.QWORD:
				val, _, err := key.GetIntegerValue(vn)
				if err != nil {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  Error: %v\n", displayName, typeName, err))
				} else {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  %d (0x%X)\n", displayName, typeName, val, val))
				}
			case registry.BINARY:
				val, _, err := key.GetBinaryValue(vn)
				if err != nil {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  Error: %v\n", displayName, typeName, err))
				} else {
					if len(val) <= 32 {
						output.WriteString(fmt.Sprintf("  %-30s  %-16s  %s\n", displayName, typeName, hex.EncodeToString(val)))
					} else {
						output.WriteString(fmt.Sprintf("  %-30s  %-16s  %s... (%d bytes)\n", displayName, typeName, hex.EncodeToString(val[:32]), len(val)))
					}
				}
			case registry.MULTI_SZ:
				val, _, err := key.GetStringsValue(vn)
				if err != nil {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  Error: %v\n", displayName, typeName, err))
				} else {
					output.WriteString(fmt.Sprintf("  %-30s  %-16s  [%s]\n", displayName, typeName, strings.Join(val, ", ")))
				}
			default:
				output.WriteString(fmt.Sprintf("  %-30s  %-16s  (binary data)\n", displayName, typeName))
			}
		}
	}

	if len(subkeys) == 0 && len(valueNames) == 0 {
		output.WriteString("(empty key)")
	}

	return output.String(), nil
}

// registryTypeName returns a human-readable name for a registry value type
func registryTypeName(valType uint32) string {
	switch valType {
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("TYPE(%d)", valType)
	}
}
