package commands

import (
	"encoding/json"
	"fmt"

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
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	output := make([]dfOutputEntry, 0, len(entries))
	for _, e := range entries {
		usePct := 0
		if e.total > 0 {
			usePct = int(float64(e.used) * 100.0 / float64(e.total))
		}
		output = append(output, dfOutputEntry{
			Filesystem: e.device,
			FsType:     e.fstype,
			MountPoint: e.mountpoint,
			TotalBytes: e.total,
			UsedBytes:  e.used,
			AvailBytes: e.avail,
			UsePercent: usePct,
		})
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
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

type dfOutputEntry struct {
	Filesystem string `json:"filesystem"`
	FsType     string `json:"fstype,omitempty"`
	MountPoint string `json:"mount_point"`
	TotalBytes uint64 `json:"total_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
	AvailBytes uint64 `json:"avail_bytes"`
	UsePercent int    `json:"use_percent"`
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
