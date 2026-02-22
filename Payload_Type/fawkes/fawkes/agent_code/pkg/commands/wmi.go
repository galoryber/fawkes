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

type WmiCommand struct{}

func (c *WmiCommand) Name() string {
	return "wmi"
}

func (c *WmiCommand) Description() string {
	return "Execute WMI queries and commands via COM API"
}

type wmiArgs struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Command string `json:"command"`
	Query   string `json:"query"`
}

func (c *WmiCommand) Execute(task structs.Task) structs.CommandResult {
	var args wmiArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: execute, query, process-list, os-info",
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
	case "execute":
		return wmiExecute(args.Target, args.Command)
	case "query":
		return wmiQuery(args.Target, args.Query)
	case "process-list":
		return wmiProcessList(args.Target)
	case "os-info":
		return wmiOsInfo(args.Target)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: execute, query, process-list, os-info", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// wmiConnection holds a WMI COM connection (SWbemLocator + SWbemServices).
type wmiConnection struct {
	locator  *ole.IDispatch
	services *ole.IDispatch
}

// wmiConnect initializes COM and connects to WMI on the given target.
// Caller must call cleanup() when done.
func wmiConnect(target string) (*wmiConnection, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		// S_FALSE means already initialized on this thread — not an error
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to create WbemScripting.SWbemLocator: %v", err)
	}

	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch on SWbemLocator: %v", err)
	}

	// ConnectServer args: server, namespace, user, password, locale, authority, securityFlags, namedValueSet
	server := ""
	if target != "" {
		server = `\\` + target
	}

	serviceResult, err := oleutil.CallMethod(locator, "ConnectServer", server, `root\CIMV2`)
	if err != nil {
		locator.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("ConnectServer failed: %v", err)
	}
	services := serviceResult.ToIDispatch()

	conn := &wmiConnection{
		locator:  locator,
		services: services,
	}

	cleanup := func() {
		services.Release()
		locator.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return conn, cleanup, nil
}

// wmiExecQuery runs a WQL query and returns results as formatted text.
func wmiExecQuery(conn *wmiConnection, wql string) (string, error) {
	resultSet, err := oleutil.CallMethod(conn.services, "ExecQuery", wql)
	if err != nil {
		return "", fmt.Errorf("ExecQuery failed: %v", err)
	}
	defer resultSet.Clear()

	resultDisp := resultSet.ToIDispatch()

	var sb strings.Builder
	itemCount := 0

	err = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		defer item.Release()

		if itemCount > 0 {
			sb.WriteString("\n---\n")
		}
		itemCount++

		// Get properties collection
		propsResult, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return fmt.Errorf("failed to get Properties_: %v", err)
		}
		defer propsResult.Clear()

		propsDisp := propsResult.ToIDispatch()

		// Iterate properties
		err = oleutil.ForEach(propsDisp, func(pv *ole.VARIANT) error {
			prop := pv.ToIDispatch()
			defer prop.Release()

			nameResult, err := oleutil.GetProperty(prop, "Name")
			if err != nil {
				return nil // skip properties we can't read
			}
			defer nameResult.Clear()

			valResult, err := oleutil.GetProperty(prop, "Value")
			if err != nil {
				sb.WriteString(fmt.Sprintf("%s=\n", nameResult.ToString()))
				return nil
			}
			defer valResult.Clear()

			name := nameResult.ToString()
			val := variantToString(valResult)
			if val != "" {
				sb.WriteString(fmt.Sprintf("%s=%s\n", name, val))
			}
			return nil
		})
		return err
	})

	if err != nil {
		return sb.String(), err
	}

	if itemCount == 0 {
		return "(no results)", nil
	}

	return sb.String(), nil
}

// variantToString converts a VARIANT to a readable string.
func variantToString(v *ole.VARIANT) string {
	if v == nil {
		return ""
	}
	switch v.VT {
	case ole.VT_NULL, ole.VT_EMPTY:
		return ""
	case ole.VT_BSTR:
		return v.ToString()
	default:
		val := v.Value()
		if val == nil {
			return ""
		}
		return fmt.Sprintf("%v", val)
	}
}

// wmiExecute creates a process on the target via WMI Win32_Process.Create
func wmiExecute(target, command string) structs.CommandResult {
	if command == "" {
		return structs.CommandResult{
			Output:    "Error: command parameter is required for execute action",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to WMI: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// Get the Win32_Process class
	classResult, err := oleutil.CallMethod(conn.services, "Get", "Win32_Process")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting Win32_Process class: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer classResult.Clear()
	classDisp := classResult.ToIDispatch()

	// Call Win32_Process.Create(CommandLine)
	// Parameters: CommandLine, CurrentDirectory, ProcessStartupInformation, ProcessId
	createResult, err := oleutil.CallMethod(classDisp, "Create", command, nil, nil)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error calling Win32_Process.Create: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer createResult.Clear()

	// The Create method returns an SWbemObject with ReturnValue and ProcessId via out params
	// However, the SWbem dispatch model returns ReturnValue directly
	retVal := createResult.Value()

	host := "localhost"
	if target != "" {
		host = target
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Process Create on %s:\n  Command: %s\n  Return Value: %v\n  (0 = Success, 2 = Access Denied, 3 = Insufficient Privilege, 8 = Unknown Failure, 21 = Invalid Parameter)", host, command, retVal),
		Status:    "success",
		Completed: true,
	}
}

// wmiQuery runs an arbitrary WQL query
func wmiQuery(target, query string) structs.CommandResult {
	if query == "" {
		return structs.CommandResult{
			Output:    "Error: query parameter is required for query action",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to WMI: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, query)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error running WMI query: %v\n%s", err, result),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Query Result:\n%s", result),
		Status:    "success",
		Completed: true,
	}
}

// wmiProcessList lists processes on the target
func wmiProcessList(target string) structs.CommandResult {
	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to WMI: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, "SELECT Name, ProcessId, HandleCount, WorkingSetSize FROM Win32_Process")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing processes: %v\n%s", err, result),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Process List:\n%s", result),
		Status:    "success",
		Completed: true,
	}
}

// wmiOsInfo gets OS information from the target
func wmiOsInfo(target string) structs.CommandResult {
	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to WMI: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting OS info: %v\n%s", err, result),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI OS Info:\n%s", result),
		Status:    "success",
		Completed: true,
	}
}
