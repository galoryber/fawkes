package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// RouteCommand enumerates the system routing table
type RouteCommand struct{}

func (c *RouteCommand) Name() string        { return "route" }
func (c *RouteCommand) Description() string { return "Display the system routing table (T1016)" }

// RouteEntry holds a single routing table entry
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Netmask     string `json:"netmask"`
	Interface   string `json:"interface"`
	Metric      uint32 `json:"metric"`
	Flags       string `json:"flags,omitempty"`
}

func (c *RouteCommand) Execute(task structs.Task) structs.CommandResult {
	routes, err := enumerateRoutes()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating routes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(routes) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	out, err := json.Marshal(routes)
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
