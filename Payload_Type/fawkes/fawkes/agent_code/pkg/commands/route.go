package commands

import (
	"encoding/json"
	"strings"

	"fawkes/pkg/structs"
)

// RouteCommand enumerates the system routing table
type RouteCommand struct{}

func (c *RouteCommand) Name() string        { return "route" }
func (c *RouteCommand) Description() string { return "Display the system routing table (T1016)" }

type routeArgs struct {
	Destination string `json:"destination"` // filter by destination IP/subnet
	Gateway     string `json:"gateway"`     // filter by gateway
	Interface   string `json:"interface"`   // filter by interface name
}

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
	var args routeArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Invalid parameters: %v", err)
		}
	}

	routes, err := enumerateRoutes()
	if err != nil {
		return errorf("Error enumerating routes: %v", err)
	}

	// Apply filters
	if args.Destination != "" || args.Gateway != "" || args.Interface != "" {
		var filtered []RouteEntry
		for _, r := range routes {
			if args.Destination != "" && !strings.Contains(r.Destination, args.Destination) {
				continue
			}
			if args.Gateway != "" && !strings.Contains(r.Gateway, args.Gateway) {
				continue
			}
			if args.Interface != "" && !strings.EqualFold(r.Interface, args.Interface) {
				continue
			}
			filtered = append(filtered, r)
		}
		routes = filtered
	}

	if len(routes) == 0 {
		return successResult("[]")
	}

	out, err := json.Marshal(routes)
	if err != nil {
		return errorf("JSON marshal error: %v", err)
	}

	return successResult(string(out))
}
