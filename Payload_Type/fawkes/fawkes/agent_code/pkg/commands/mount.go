package commands

import (
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

func (c *MountCommand) Execute(task structs.Task) structs.CommandResult {
	entries, err := getMountInfo()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[*] No mount points found",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d mount points\n\n", len(entries)))
	sb.WriteString(fmt.Sprintf("%-30s %-20s %-12s %s\n", "Device", "Mount Point", "Type", "Options"))
	sb.WriteString(fmt.Sprintf("%-30s %-20s %-12s %s\n", "------", "-----------", "----", "-------"))

	for _, e := range entries {
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
