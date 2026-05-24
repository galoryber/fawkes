package commands

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// ModulesCommand lists loaded modules/DLLs/libraries in a process
type ModulesCommand struct{}

func (c *ModulesCommand) Name() string { return "modules" }
func (c *ModulesCommand) Description() string {
	return "List loaded modules/DLLs/libraries in a process (T1057)"
}

type modulesArgs struct {
	PID    int    `json:"pid"`
	Filter string `json:"filter"` // filter by module name (case-insensitive substring)
}

// ModuleInfo represents a loaded module/library
type ModuleInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BaseAddr string `json:"base_addr"`
	Size     uint64 `json:"size"`
}

func (c *ModulesCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[modulesArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.PID <= 0 {
		args.PID = os.Getpid()
	}

	modules, err := listProcessModules(args.PID)
	if err != nil {
		return errorf("Error listing modules for PID %d: %v", args.PID, err)
	}

	// Sort by base address
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].BaseAddr < modules[j].BaseAddr
	})

	// Apply name filter
	if args.Filter != "" {
		filterLower := strings.ToLower(args.Filter)
		var filtered []ModuleInfo
		for _, m := range modules {
			if strings.Contains(strings.ToLower(m.Name), filterLower) || strings.Contains(strings.ToLower(m.Path), filterLower) {
				filtered = append(filtered, m)
			}
		}
		modules = filtered
	}

	if len(modules) == 0 {
		return successResult("[]")
	}

	out, err := json.Marshal(modules)
	if err != nil {
		return errorf("JSON marshal error: %v", err)
	}

	return successResult(string(out))
}
