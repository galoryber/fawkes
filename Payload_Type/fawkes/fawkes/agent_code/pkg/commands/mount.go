package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// MountCommand implements filesystem mount point listing
type MountCommand struct{}

func (c *MountCommand) Name() string {
	return "mount"
}

func (c *MountCommand) Description() string {
	return "List mounted filesystems and their types"
}

type mountArgs struct {
	Filter string `json:"filter"`
	FsType string `json:"fstype"`
}

func (c *MountCommand) Execute(task structs.Task) structs.CommandResult {
	var args mountArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args) // best-effort; proceed with defaults on error
	}

	entries, err := getMountInfo()
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Apply filters
	filterLower := strings.ToLower(args.Filter)
	fstypeLower := strings.ToLower(args.FsType)
	var filtered []mountInfoEntry
	for _, e := range entries {
		if filterLower != "" {
			lower := strings.ToLower(e.device + " " + e.mntPoint)
			if !strings.Contains(lower, filterLower) {
				continue
			}
		}
		if fstypeLower != "" && !strings.EqualFold(e.mntType, fstypeLower) {
			continue
		}
		filtered = append(filtered, e)
	}

	if len(filtered) == 0 && len(entries) == 0 {
		return successResult("[*] No mount points found")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d mount points", len(entries)))
	if filterLower != "" || fstypeLower != "" {
		sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
	}
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("%-30s %-20s %-12s %s\n", "Device", "Mount Point", "Type", "Options"))
	sb.WriteString(fmt.Sprintf("%-30s %-20s %-12s %s\n", "------", "-----------", "----", "-------"))

	for _, e := range filtered {
		sb.WriteString(fmt.Sprintf("%-30s %-20s %-12s %s\n",
			truncStr(e.device, 30),
			truncStr(e.mntPoint, 20),
			e.mntType,
			truncStr(e.mntOpts, 50)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

type mountInfoEntry struct {
	device   string
	mntPoint string
	mntType  string
	mntOpts  string
}
