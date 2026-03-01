package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// UptimeCommand shows system uptime and boot time
type UptimeCommand struct{}

func (c *UptimeCommand) Name() string        { return "uptime" }
func (c *UptimeCommand) Description() string { return "Show system uptime and boot time" }

func (c *UptimeCommand) Execute(task structs.Task) structs.CommandResult {
	output := uptimePlatform()
	if output == "" {
		output = "Unable to determine system uptime on this platform"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// formatUptime formats a duration in seconds to a human-readable string
func formatUptime(totalSeconds int64) string {
	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d day(s)", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hour(s)", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minute(s)", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d second(s)", seconds))
	}
	return strings.Join(parts, ", ")
}
