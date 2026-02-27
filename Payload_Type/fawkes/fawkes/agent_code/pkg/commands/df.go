package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// DfCommand implements disk free space reporting
type DfCommand struct{}

func (c *DfCommand) Name() string {
	return "df"
}

func (c *DfCommand) Description() string {
	return "Report filesystem disk space usage"
}

func (c *DfCommand) Execute(task structs.Task) structs.CommandResult {
	entries, err := getDiskFreeInfo()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[*] No filesystems found",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-20s %-10s %-10s %-10s %-6s %s\n",
		"Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"))
	sb.WriteString(fmt.Sprintf("%-20s %-10s %-10s %-10s %-6s %s\n",
		"----------", "----", "----", "-----", "----", "----------"))

	for _, e := range entries {
		usePct := 0
		if e.total > 0 {
			usePct = int(float64(e.used) * 100.0 / float64(e.total))
		}
		sb.WriteString(fmt.Sprintf("%-20s %-10s %-10s %-10s %3d%%   %s\n",
			truncStr(e.device, 20),
			statFormatSize(int64(e.total)),
			statFormatSize(int64(e.used)),
			statFormatSize(int64(e.avail)),
			usePct,
			e.mountpoint))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

type dfEntry struct {
	device     string
	fstype     string
	mountpoint string
	total      uint64
	used       uint64
	avail      uint64
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
