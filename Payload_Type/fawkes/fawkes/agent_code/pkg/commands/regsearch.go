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

type RegSearchCommand struct{}

func (c *RegSearchCommand) Name() string { return "reg-search" }
func (c *RegSearchCommand) Description() string {
	return "Search Windows Registry keys and values recursively (T1012)"
}

type regSearchArgs struct {
	Hive       string `json:"hive"`
	Path       string `json:"path"`
	Pattern    string `json:"pattern"`
	MaxDepth   int    `json:"max_depth"`
	MaxResults int    `json:"max_results"`
}

type regSearchResult struct {
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name,omitempty"`
	ValueData string `json:"value_data,omitempty"`
}

func (c *RegSearchCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -hive <HKLM|HKCU|HKU|HKCR> -path <path> -pattern <search>",
			Status:    "error",
			Completed: true,
		}
	}

	var args regSearchArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Pattern == "" {
		return structs.CommandResult{
			Output:    "Error: pattern is required",
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

	hiveKey, err := regSearchParseHive(args.Hive)
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

func regSearchParseHive(hive string) (registry.Key, error) {
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unknown hive: %s (use HKLM, HKCU, HKU, HKCR, HKCC)", hive)
	}
}

func regSearchRecursive(hive registry.Key, path, pattern string, depth, maxDepth, maxResults int, results *[]regSearchResult) {
	if depth >= maxDepth || len(*results) >= maxResults {
		return
	}

	key, err := registry.OpenKey(hive, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	// Check if the key name itself matches
	keyLower := strings.ToLower(path)
	if strings.Contains(keyLower, pattern) && len(*results) < maxResults {
		*results = append(*results, regSearchResult{
			KeyPath: path,
		})
	}

	// Search value names and data
	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			if len(*results) >= maxResults {
				return
			}
			nameLower := strings.ToLower(name)
			dataStr := regSearchReadValue(key, name)
			dataLower := strings.ToLower(dataStr)

			if strings.Contains(nameLower, pattern) || strings.Contains(dataLower, pattern) {
				*results = append(*results, regSearchResult{
					KeyPath:   path,
					ValueName: name,
					ValueData: dataStr,
				})
			}
		}
	}

	// Recurse into subkeys
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, sub := range subKeys {
		if len(*results) >= maxResults {
			return
		}
		subPath := path + `\` + sub
		regSearchRecursive(hive, subPath, pattern, depth+1, maxDepth, maxResults, results)
	}
}

func regSearchReadValue(key registry.Key, name string) string {
	// Try string first (most common)
	val, _, err := key.GetStringValue(name)
	if err == nil {
		return val
	}

	// Try integer
	intVal, _, err := key.GetIntegerValue(name)
	if err == nil {
		return fmt.Sprintf("%d (0x%x)", intVal, intVal)
	}

	// Try binary — show first 64 bytes hex
	binVal, _, err := key.GetBinaryValue(name)
	if err == nil {
		if len(binVal) > 64 {
			return fmt.Sprintf("(binary %d bytes) %x...", len(binVal), binVal[:64])
		}
		return fmt.Sprintf("(binary %d bytes) %x", len(binVal), binVal)
	}

	// Try multi-string
	strVals, _, err := key.GetStringsValue(name)
	if err == nil {
		return strings.Join(strVals, "; ")
	}

	return "(unreadable)"
}
