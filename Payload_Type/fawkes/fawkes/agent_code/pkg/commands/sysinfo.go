package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// SysinfoCommand collects comprehensive system information
type SysinfoCommand struct{}

func (c *SysinfoCommand) Name() string        { return "sysinfo" }
func (c *SysinfoCommand) Description() string { return "Collect comprehensive system information (T1082)" }

func (c *SysinfoCommand) Execute(task structs.Task) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("System Information\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Common info available everywhere
	hostname, _ := os.Hostname()
	sb.WriteString(fmt.Sprintf("Hostname:      %s\n", hostname))
	sb.WriteString(fmt.Sprintf("OS:            %s\n", runtime.GOOS))
	sb.WriteString(fmt.Sprintf("Architecture:  %s\n", runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("CPUs:          %d\n", runtime.NumCPU()))
	sb.WriteString(fmt.Sprintf("Go Version:    %s\n", runtime.Version()))
	sb.WriteString(fmt.Sprintf("PID:           %d\n", os.Getpid()))
	sb.WriteString(fmt.Sprintf("PPID:          %d\n", os.Getppid()))

	wd, _ := os.Getwd()
	sb.WriteString(fmt.Sprintf("Working Dir:   %s\n", wd))

	// Current time and timezone
	now := time.Now()
	zone, offset := now.Zone()
	sb.WriteString(fmt.Sprintf("Time:          %s\n", now.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Timezone:      %s (UTC%+d)\n", zone, offset/3600))

	// Platform-specific information
	sb.WriteString("\n")
	collectPlatformSysinfo(&sb)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
