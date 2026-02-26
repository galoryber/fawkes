package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// DriversCommand enumerates loaded kernel drivers/modules
type DriversCommand struct{}

func (c *DriversCommand) Name() string        { return "drivers" }
func (c *DriversCommand) Description() string { return "Enumerate loaded kernel drivers and modules (T1082)" }

type driversArgs struct {
	Filter string `json:"filter"` // Optional name filter
}

// DriverInfo holds info about a loaded driver/module
type DriverInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Status  string `json:"status"`
	Size    uint64 `json:"size,omitempty"`
	Version string `json:"version,omitempty"`
}

func (c *DriversCommand) Execute(task structs.Task) structs.CommandResult {
	var args driversArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Treat as plain filter string
			args.Filter = strings.TrimSpace(task.Params)
		}
	}

	drivers, err := enumerateDrivers()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating drivers: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Apply filter
	filterLower := strings.ToLower(args.Filter)
	var filtered []DriverInfo
	for _, d := range drivers {
		if filterLower != "" {
			if !strings.Contains(strings.ToLower(d.Name), filterLower) &&
				!strings.Contains(strings.ToLower(d.Path), filterLower) {
				continue
			}
		}
		filtered = append(filtered, d)
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Loaded Drivers/Modules: %d", len(filtered)))
	if args.Filter != "" {
		sb.WriteString(fmt.Sprintf(" (filter: %s, total: %d)", args.Filter, len(drivers)))
	}
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%-30s %-12s %-55s %s\n", "Name", "Size", "Path", "Status"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")

	for _, d := range filtered {
		sizeStr := "-"
		if d.Size > 0 {
			sizeStr = formatFileSize(int64(d.Size))
		}
		path := d.Path
		if path == "" {
			path = "-"
		}
		status := d.Status
		if status == "" {
			status = "loaded"
		}
		sb.WriteString(fmt.Sprintf("%-30s %-12s %-55s %s\n", d.Name, sizeStr, path, status))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
