//go:build windows
// +build windows

package commands

import (
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
	return "Create, query, run, or delete scheduled tasks via Task Scheduler COM API"
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
}

// Task Scheduler 2.0 COM constants
const (
	// Task trigger types
	TASK_TRIGGER_LOGON  = 9
	TASK_TRIGGER_BOOT   = 8
	TASK_TRIGGER_DAILY  = 2
	TASK_TRIGGER_WEEKLY = 3
	TASK_TRIGGER_IDLE   = 6
	TASK_TRIGGER_TIME   = 1

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
		return structs.CommandResult{
			Output:    "Error: parameters required (action, name)",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return schtaskList()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: create, query, delete, run, list", args.Action),
			Status:    "error",
			Completed: true,
		}
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

// triggerTypeFromString maps trigger name to Task Scheduler 2.0 trigger type constant.
func triggerTypeFromString(trigger string) int {
	switch strings.ToUpper(trigger) {
	case "ONLOGON":
		return TASK_TRIGGER_LOGON
	case "ONSTART":
		return TASK_TRIGGER_BOOT
	case "DAILY":
		return TASK_TRIGGER_DAILY
	case "WEEKLY":
		return TASK_TRIGGER_WEEKLY
	case "ONIDLE":
		return TASK_TRIGGER_IDLE
	case "ONCE":
		return TASK_TRIGGER_TIME
	default:
		return TASK_TRIGGER_LOGON
	}
}

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
    <Description>Created by Fawkes</Description>
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

// buildTriggerXML generates the trigger section of the task XML.
func buildTriggerXML(trigger, startTime string) string {
	switch strings.ToUpper(trigger) {
	case "ONLOGON":
		return "    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>"
	case "ONSTART":
		return "    <BootTrigger>\n      <Enabled>true</Enabled>\n    </BootTrigger>"
	case "ONIDLE":
		return "    <IdleTrigger>\n      <Enabled>true</Enabled>\n    </IdleTrigger>"
	case "DAILY":
		boundary := "2026-01-01T09:00:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <CalendarTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n    </CalendarTrigger>", boundary)
	case "WEEKLY":
		boundary := "2026-01-01T09:00:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <CalendarTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByWeek>\n        <WeeksInterval>1</WeeksInterval>\n        <DaysOfWeek><Monday /></DaysOfWeek>\n      </ScheduleByWeek>\n    </CalendarTrigger>", boundary)
	case "ONCE":
		boundary := "2026-12-31T23:59:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <TimeTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n    </TimeTrigger>", boundary)
	default:
		return "    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>"
	}
}

// escapeXML escapes special characters for XML content.
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func schtaskCreate(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for task creation",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Program == "" {
		return structs.CommandResult{
			Output:    "Error: program is required for task creation",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to Task Scheduler: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error registering task '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    "Error: name is required for task query",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to Task Scheduler: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying task '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    "Error: name is required for task deletion",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to Task Scheduler: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	_, err = oleutil.CallMethod(conn.folder, "DeleteTask", args.Name, 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting task '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted scheduled task '%s'", args.Name),
		Status:    "success",
		Completed: true,
	}
}

func schtaskRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to run a task",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to Task Scheduler: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	taskResult, err := oleutil.CallMethod(conn.folder, "GetTask", args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding task '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer taskResult.Clear()
	taskDisp := taskResult.ToIDispatch()

	runResult, err := oleutil.CallMethod(taskDisp, "Run", nil)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error running task '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	runResult.Clear()

	return structs.CommandResult{
		Output:    fmt.Sprintf("Triggered execution of '%s'", args.Name),
		Status:    "success",
		Completed: true,
	}
}

func schtaskList() structs.CommandResult {
	conn, cleanup, err := connectTaskScheduler()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to Task Scheduler: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// Get tasks from root folder (0 = include hidden tasks)
	tasksResult, err := oleutil.CallMethod(conn.folder, "GetTasks", 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing tasks: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer tasksResult.Clear()
	tasksDisp := tasksResult.ToIDispatch()

	var sb strings.Builder
	sb.WriteString("Scheduled Tasks (root folder):\n\n")
	sb.WriteString(fmt.Sprintf("%-40s %-12s %-8s %s\n", "Name", "State", "Enabled", "Next Run Time"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	taskCount := 0
	oleutil.ForEach(tasksDisp, func(v *ole.VARIANT) error {
		taskDisp := v.ToIDispatch()
		// Note: do NOT Release taskDisp — ForEach manages the VARIANT lifecycle
		taskCount++

		nameResult, _ := oleutil.GetProperty(taskDisp, "Name")
		name := ""
		if nameResult != nil {
			name = nameResult.ToString()
			nameResult.Clear()
		}

		stateResult, _ := oleutil.GetProperty(taskDisp, "State")
		state := ""
		if stateResult != nil {
			state = taskStateToString(stateResult.Value())
			stateResult.Clear()
		}

		enabledResult, _ := oleutil.GetProperty(taskDisp, "Enabled")
		enabled := ""
		if enabledResult != nil {
			enabled = fmt.Sprintf("%v", enabledResult.Value())
			enabledResult.Clear()
		}

		nextRunResult, _ := oleutil.GetProperty(taskDisp, "NextRunTime")
		nextRun := ""
		if nextRunResult != nil {
			nextRun = fmt.Sprintf("%v", nextRunResult.Value())
			nextRunResult.Clear()
		}

		sb.WriteString(fmt.Sprintf("%-40s %-12s %-8s %s\n", name, state, enabled, nextRun))
		return nil
	})

	sb.WriteString(fmt.Sprintf("\nTotal: %d tasks\n", taskCount))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
