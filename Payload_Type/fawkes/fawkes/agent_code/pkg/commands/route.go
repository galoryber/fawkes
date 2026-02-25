package commands

import (
	"fmt"
	"strings"

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
			Output:    "No routes found",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Routing Table: %d entries\n\n", len(routes)))
	sb.WriteString(fmt.Sprintf("%-20s %-20s %-20s %-15s %-8s %s\n",
		"Destination", "Gateway", "Netmask", "Interface", "Metric", "Flags"))
	sb.WriteString(strings.Repeat("-", 95) + "\n")

	for _, r := range routes {
		gw := r.Gateway
		if gw == "" {
			gw = "*"
		}
		flags := r.Flags
		if flags == "" {
			flags = "-"
		}
		sb.WriteString(fmt.Sprintf("%-20s %-20s %-20s %-15s %-8d %s\n",
			r.Destination, gw, r.Netmask, r.Interface, r.Metric, flags))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
