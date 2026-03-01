package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"fawkes/pkg/structs"
)

// ModulesCommand lists loaded modules/DLLs/libraries in a process
type ModulesCommand struct{}

func (c *ModulesCommand) Name() string { return "modules" }
func (c *ModulesCommand) Description() string {
	return "List loaded modules/DLLs/libraries in a process (T1057)"
}

type modulesArgs struct {
	PID int `json:"pid"`
}

// ModuleInfo represents a loaded module/library
type ModuleInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BaseAddr string `json:"base_addr"`
	Size     uint64 `json:"size"`
}

func (c *ModulesCommand) Execute(task structs.Task) structs.CommandResult {
	var args modulesArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.PID <= 0 {
		args.PID = os.Getpid()
	}

	modules, err := listProcessModules(args.PID)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing modules for PID %d: %v", args.PID, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Sort by base address
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].BaseAddr < modules[j].BaseAddr
	})

	if len(modules) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	out, err := json.Marshal(modules)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("JSON marshal error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(out),
		Status:    "success",
		Completed: true,
	}
}

func formatModuleSize(size uint64) string {
	if size >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
	if size >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}
