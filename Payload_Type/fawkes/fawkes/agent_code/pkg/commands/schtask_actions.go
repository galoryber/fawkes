//go:build windows
// +build windows

package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

func schtaskCreate(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for task creation")
	}
	if args.Program == "" {
		return errorResult("program is required for task creation")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	trigger := args.Trigger
	if trigger == "" {
		trigger = "ONLOGON"
	}

	// Build task XML and register via RegisterTask (XML-based, avoids COM object deadlocks)
	taskXML := buildTaskXML(args)

	// RegisterTask(path, xmlText, flags, userId, password, logonType)
	// TASK_CREATE_OR_UPDATE = 6, TASK_LOGON_S4U = 2
	logonType := TASK_LOGON_S4U
	var userParam interface{} = nil
	if args.User != "" {
		userParam = args.User
		if strings.EqualFold(args.User, "SYSTEM") || strings.EqualFold(args.User, "NT AUTHORITY\\SYSTEM") {
			logonType = TASK_LOGON_SERVICE_ACCOUNT
			userParam = "SYSTEM"
		} else {
			logonType = TASK_LOGON_INTERACTIVE_TOKEN_OR_PWD
		}
	}

	regResult, err := oleutil.CallMethod(conn.folder, "RegisterTask",
		args.Name, taskXML, TASK_CREATE_OR_UPDATE, userParam, nil, logonType, nil)
	if err != nil {
		return errorf("registering task '%s': %v", args.Name, err)
	}
	regResult.Clear()

	result := fmt.Sprintf("Created scheduled task:\n  Name:    %s\n  Program: %s\n  Trigger: %s", args.Name, args.Program, trigger)
	if args.User != "" {
		result += fmt.Sprintf("\n  User:    %s", args.User)
	}

	// Optionally run immediately
	if args.RunNow {
		taskResult, getErr := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
		if getErr == nil {
			taskDisp := taskResult.ToIDispatch()
			runResult, runErr := oleutil.CallMethod(taskDisp, "Run", nil)
			if runErr != nil {
				result += fmt.Sprintf("\n\nWarning: Task created but immediate run failed: %v", runErr)
			} else {
				result += "\n\nTask executed immediately"
				runResult.Clear()
			}
			taskDisp.Release()
			taskResult.Clear()
		}
	}

	return successResult(result)
}

func schtaskQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for task query")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("querying task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Task: %s\n", args.Name))

	// Get task state
	stateResult, _ := oleutil.GetProperty(taskDisp, "State")
	if stateResult != nil {
		state := stateResult.Value()
		sb.WriteString(fmt.Sprintf("State: %s\n", taskStateToString(state)))
		stateResult.Clear()
	}

	// Get enabled status
	enabledResult, _ := oleutil.GetProperty(taskDisp, "Enabled")
	if enabledResult != nil {
		sb.WriteString(fmt.Sprintf("Enabled: %v\n", enabledResult.Value()))
		enabledResult.Clear()
	}

	// Get last run time
	lastRunResult, _ := oleutil.GetProperty(taskDisp, "LastRunTime")
	if lastRunResult != nil {
		sb.WriteString(fmt.Sprintf("Last Run Time: %v\n", lastRunResult.Value()))
		lastRunResult.Clear()
	}

	// Get next run time
	nextRunResult, _ := oleutil.GetProperty(taskDisp, "NextRunTime")
	if nextRunResult != nil {
		sb.WriteString(fmt.Sprintf("Next Run Time: %v\n", nextRunResult.Value()))
		nextRunResult.Clear()
	}

	// Get last task result
	lastResultProp, _ := oleutil.GetProperty(taskDisp, "LastTaskResult")
	if lastResultProp != nil {
		sb.WriteString(fmt.Sprintf("Last Result: %v\n", lastResultProp.Value()))
		lastResultProp.Clear()
	}

	// Get task XML for detailed info (safer than navigating nested COM objects)
	xmlResult, err := oleutil.GetProperty(taskDisp, "Xml")
	if err == nil && xmlResult != nil {
		xmlStr := xmlResult.ToString()
		xmlResult.Clear()
		// Extract key info from XML
		if desc := extractXMLValue(xmlStr, "Description"); desc != "" {
			sb.WriteString(fmt.Sprintf("Description: %s\n", desc))
		}
		if author := extractXMLValue(xmlStr, "Author"); author != "" {
			sb.WriteString(fmt.Sprintf("Author: %s\n", author))
		}
		if cmd := extractXMLValue(xmlStr, "Command"); cmd != "" {
			sb.WriteString(fmt.Sprintf("Action Path: %s\n", cmd))
		}
		if cmdArgs := extractXMLValue(xmlStr, "Arguments"); cmdArgs != "" {
			sb.WriteString(fmt.Sprintf("Action Args: %s\n", cmdArgs))
		}
	}

	return successResult(sb.String())
}

func schtaskDelete(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for task deletion")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	_, err = oleutil.CallMethod(conn.folder, "DeleteTask", args.Name, 0)
	if err != nil {
		return errorf("deleting task '%s': %v", args.Name, err)
	}

	return successf("Deleted scheduled task '%s'", args.Name)
}

func schtaskRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to run a task")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	runResult, err := oleutil.CallMethod(taskDisp, "Run", nil)
	if err != nil {
		return errorf("running task '%s': %v", args.Name, err)
	}
	runResult.Clear()

	return successf("Triggered execution of '%s'", args.Name)
}

// schtaskListEntry represents a scheduled task for JSON output
type schtaskListEntry struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	NextRunTime string `json:"next_run_time,omitempty"`
	Author      string `json:"author,omitempty"`
	RunAsUser   string `json:"run_as_user,omitempty"`
	TaskToRun   string `json:"task_to_run,omitempty"`
	StartIn     string `json:"start_in,omitempty"`
	LastRunTime string `json:"last_run_time,omitempty"`
	LastResult  string `json:"last_result,omitempty"`
	LogonMode   string `json:"logon_mode,omitempty"`
	Enabled     string `json:"enabled,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

func schtaskList(filter string) structs.CommandResult {
	// Use schtasks.exe /query /fo CSV /v — verbose mode includes Author,
	// Run As User, and Task To Run which are critical for privesc analysis.
	// COM-based iteration (ForEach, Count+Item) hangs in Go's COM apartment model.
	out, err := execCmdTimeout("schtasks.exe", "/query", "/fo", "CSV", "/v")
	if err != nil {
		return errorf("running schtasks.exe: %v\n%s", err, string(out))
	}

	filterLower := strings.ToLower(filter)
	var entries []schtaskListEntry

	// Verbose CSV columns (header row present with /v):
	// 0:HostName, 1:TaskName, 2:Next Run Time, 3:Status, 4:Logon Mode,
	// 5:Last Run Time, 6:Last Result, 7:Author, 8:Task To Run, 9:Start In, ...
	// 14:Run As User, ...
	reader := csv.NewReader(strings.NewReader(string(out)))
	reader.LazyQuotes = true
	headerSkipped := false
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) < 15 {
			continue
		}

		name := strings.TrimSpace(record[1])
		if !headerSkipped {
			if name == "TaskName" {
				headerSkipped = true
			}
			continue
		}
		if name == "" || name == "INFO:" {
			continue
		}
		if filterLower != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		enabled := "true"
		if len(record) > 11 && strings.EqualFold(strings.TrimSpace(record[11]), "Disabled") {
			enabled = "false"
		}

		startIn := strings.TrimSpace(record[9])
		if startIn == "N/A" {
			startIn = ""
		}
		comment := ""
		if len(record) > 10 {
			comment = strings.TrimSpace(record[10])
			if comment == "N/A" {
				comment = ""
			}
		}

		entries = append(entries, schtaskListEntry{
			Name:        name,
			State:       strings.TrimSpace(record[3]),
			NextRunTime: strings.TrimSpace(record[2]),
			Author:      strings.TrimSpace(record[7]),
			RunAsUser:   strings.TrimSpace(record[14]),
			TaskToRun:   strings.TrimSpace(record[8]),
			StartIn:     startIn,
			LastRunTime: strings.TrimSpace(record[5]),
			LastResult:  strings.TrimSpace(record[6]),
			LogonMode:   strings.TrimSpace(record[4]),
			Enabled:     enabled,
			Comment:     comment,
		})
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("marshaling results: %v", err)
	}

	return successResult(string(data))
}

// schtaskSetEnabled enables or disables a scheduled task via IRegisteredTask.put_Enabled.
func schtaskSetEnabled(args schtaskArgs, enabled bool) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	_, err = oleutil.PutProperty(taskDisp, "Enabled", enabled)
	if err != nil {
		return errorf("setting enabled state for '%s': %v", args.Name, err)
	}

	action := "Enabled"
	if !enabled {
		action = "Disabled"
	}
	return successf("%s scheduled task '%s'", action, args.Name)
}

// schtaskStop stops a currently-running scheduled task instance.
func schtaskStop(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to stop a task")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	_, err = oleutil.CallMethod(taskDisp, "Stop", 0)
	if err != nil {
		return errorf("stopping task '%s': %v", args.Name, err)
	}

	return successf("Stopped running instance of '%s'", args.Name)
}
