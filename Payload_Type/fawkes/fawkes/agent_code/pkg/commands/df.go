package commands

import (
	"encoding/json"
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

type dfArgs struct {
	Filesystem string `json:"filesystem"`  // filter by device name (substring)
	MountPoint string `json:"mount_point"` // filter by mount point (substring)
	FsType     string `json:"fstype"`      // filter by filesystem type (case-insensitive)
}

func (c *DfCommand) Execute(task structs.Task) structs.CommandResult {
	var args dfArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Invalid parameters: %v", err)
		}
	}

	entries, err := getDiskFreeInfo()
	if err != nil {
		return errorf("Error: %v", err)
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	output := make([]dfOutputEntry, 0, len(entries))
	for _, e := range entries {
		if args.Filesystem != "" && !strings.Contains(e.device, args.Filesystem) {
			continue
		}
		if args.MountPoint != "" && !strings.Contains(e.mountpoint, args.MountPoint) {
			continue
		}
		if args.FsType != "" && !strings.EqualFold(e.fstype, args.FsType) {
			continue
		}

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

	if len(output) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error: %v", err)
	}

	return successResult(string(jsonBytes))
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

// truncStr moved to format_helpers.go
