package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// ProcessTreeCommand displays processes in a tree hierarchy
type ProcessTreeCommand struct{}

func (c *ProcessTreeCommand) Name() string        { return "process-tree" }
func (c *ProcessTreeCommand) Description() string { return "Display process hierarchy as a tree" }

type processTreeArgs struct {
	Filter string `json:"filter"`
	PID    int32  `json:"pid"` // root PID to start from (0 = all)
}

func (c *ProcessTreeCommand) Execute(task structs.Task) structs.CommandResult {
	var args processTreeArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Invalid parameters: %v", err)
		}
	}

	processes, err := getProcessList(PsArgs{})
	if err != nil {
		return errorf("Error listing processes: %v", err)
	}

	// Build parent->children map
	byPID := make(map[int32]ProcessInfo)
	children := make(map[int32][]int32)
	for _, p := range processes {
		byPID[p.PID] = p
		// Skip self-referencing parents (e.g., Windows PID 0 has PPID 0)
		// to prevent infinite recursion in the tree printer.
		if p.PID != p.PPID {
			children[p.PPID] = append(children[p.PPID], p.PID)
		}
	}

	// Sort children by PID for stable output
	for ppid := range children {
		kids := children[ppid]
		sort.Slice(kids, func(i, j int) bool { return kids[i] < kids[j] })
	}

	filterLower := strings.ToLower(args.Filter)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d processes\n\n", len(processes)))

	// Recursive tree printer
	var printTree func(pid int32, prefix string, isLast bool, depth int)
	printTree = func(pid int32, prefix string, isLast bool, depth int) {
		p, ok := byPID[pid]
		if !ok {
			return
		}

		// Apply filter
		if filterLower != "" && !strings.Contains(strings.ToLower(p.Name), filterLower) {
			// Still recurse into children in case they match
			kids := children[pid]
			for i, childPID := range kids {
				newPrefix := prefix
				if depth > 0 {
					if isLast {
						newPrefix += "    "
					} else {
						newPrefix += "|   "
					}
				}
				printTree(childPID, newPrefix, i == len(kids)-1, depth+1)
			}
			return
		}

		// Print this node
		connector := ""
		if depth > 0 {
			if isLast {
				connector = "`-- "
			} else {
				connector = "|-- "
			}
		}

		userStr := ""
		if p.User != "" {
			userStr = fmt.Sprintf(" [%s]", p.User)
		}

		sb.WriteString(fmt.Sprintf("%s%s%d: %s%s\n", prefix, connector, p.PID, p.Name, userStr))

		// Print children
		kids := children[pid]
		for i, childPID := range kids {
			newPrefix := prefix
			if depth > 0 {
				if isLast {
					newPrefix += "    "
				} else {
					newPrefix += "|   "
				}
			}
			printTree(childPID, newPrefix, i == len(kids)-1, depth+1)
		}
	}

	if args.PID > 0 {
		// Start from specific PID
		if _, ok := byPID[args.PID]; ok {
			printTree(args.PID, "", true, 0)
		} else {
			return errorf("Error: PID %d not found", args.PID)
		}
	} else {
		// Find root processes (PPID not in our process list, or PPID=0)
		var roots []int32
		for _, p := range processes {
			if _, parentExists := byPID[p.PPID]; !parentExists || p.PPID == 0 {
				roots = append(roots, p.PID)
			}
		}
		sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

		for i, rootPID := range roots {
			printTree(rootPID, "", i == len(roots)-1, 0)
		}
	}

	out := sb.String()
	if len(out) > 200000 {
		out = out[:200000] + "\n... (truncated)"
	}

	return successResult(out)
}
