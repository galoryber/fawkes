//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

type DefenderCommand struct{}

func (c *DefenderCommand) Name() string {
	return "defender"
}

func (c *DefenderCommand) Description() string {
	return "Query Windows Defender status, manage exclusions, and view threat history"
}

type defenderArgs struct {
	Action string `json:"action"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

func (c *DefenderCommand) Execute(task structs.Task) structs.CommandResult {
	var args defenderArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: status, exclusions, add-exclusion, remove-exclusion, threats",
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
	case "status":
		return defenderStatus()
	case "exclusions":
		return defenderExclusions()
	case "add-exclusion":
		return defenderAddExclusion(args)
	case "remove-exclusion":
		return defenderRemoveExclusion(args)
	case "threats":
		return defenderThreats()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: status, exclusions, add-exclusion, remove-exclusion, threats", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// defenderWMIQuery connects to root\Microsoft\Windows\Defender and runs a WQL query.
func defenderWMIQuery(wql string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return "", fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return "", fmt.Errorf("failed to create SWbemLocator: %v", err)
	}
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		return "", fmt.Errorf("failed to query IDispatch: %v", err)
	}
	defer locator.Release()

	serviceResult, err := oleutil.CallMethod(locator, "ConnectServer", "", `root\Microsoft\Windows\Defender`)
	if err != nil {
		return "", fmt.Errorf("ConnectServer failed: %v (is Windows Defender installed?)", err)
	}
	services := serviceResult.ToIDispatch()
	defer services.Release()

	resultSet, err := oleutil.CallMethod(services, "ExecQuery", wql)
	if err != nil {
		return "", fmt.Errorf("ExecQuery failed: %v", err)
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

		propsResult, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return fmt.Errorf("failed to get Properties_: %v", err)
		}
		defer propsResult.Clear()
		propsDisp := propsResult.ToIDispatch()

		err = oleutil.ForEach(propsDisp, func(pv *ole.VARIANT) error {
			prop := pv.ToIDispatch()
			// Note: do NOT Release prop — ForEach manages the VARIANT lifecycle

			nameResult, err := oleutil.GetProperty(prop, "Name")
			if err != nil {
				return nil
			}
			defer nameResult.Clear()

			valResult, err := oleutil.GetProperty(prop, "Value")
			if err != nil {
				sb.WriteString(fmt.Sprintf("%s=\n", nameResult.ToString()))
				return nil
			}
			defer valResult.Clear()

			name := nameResult.ToString()
			val := defenderVariantToString(valResult)
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

// defenderVariantToString converts a VARIANT to a readable string.
func defenderVariantToString(v *ole.VARIANT) string {
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

// defenderWMIQueryWithTimeout runs a WMI query with a timeout to prevent agent hangs.
func defenderWMIQueryWithTimeout(wql string, timeout time.Duration) (string, error) {
	type wmiResult struct {
		output string
		err    error
	}
	ch := make(chan wmiResult, 1)
	go func() {
		out, err := defenderWMIQuery(wql)
		ch <- wmiResult{out, err}
	}()
	select {
	case r := <-ch:
		return r.output, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("WMI query timed out after %v", timeout)
	}
}

// defenderStatus gets Defender status, trying registry first (fast), then WMI.
func defenderStatus() structs.CommandResult {
	// Registry is faster and more reliable — try it first
	regResult := defenderStatusRegistry()

	// Also try WMI for additional details (with timeout to prevent hangs)
	wmiResult, err := defenderWMIQueryWithTimeout(
		"SELECT AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, "+
			"BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, "+
			"RealTimeProtectionEnabled, QuickScanAge, FullScanAge, ComputerState FROM MSFT_MpComputerStatus",
		15*time.Second,
	)
	if err == nil && wmiResult != "" && wmiResult != "(no results)" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Windows Defender Status:\n\n%s\n\n--- Registry Details ---\n%s", wmiResult, regResult.Output),
			Status:    "success",
			Completed: true,
		}
	}

	// WMI failed or timed out — return registry results
	return regResult
}

// defenderStatusRegistry reads Defender status from the registry as a fallback.
func defenderStatusRegistry() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Windows Defender Status (from registry):\n\n")

	// Check if Defender is disabled via policy
	policyKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows Defender`, registry.READ)
	if err == nil {
		val, _, err := policyKey.GetIntegerValue("DisableAntiSpyware")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  Policy DisableAntiSpyware: %d\n", val))
		}
		val, _, err = policyKey.GetIntegerValue("DisableAntiVirus")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  Policy DisableAntiVirus: %d\n", val))
		}
		policyKey.Close()
	}

	// Real-time protection settings
	rtpKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, registry.READ)
	if err == nil {
		val, _, err := rtpKey.GetIntegerValue("DisableRealtimeMonitoring")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  DisableRealtimeMonitoring: %d\n", val))
		}
		val, _, err = rtpKey.GetIntegerValue("DisableBehaviorMonitoring")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  DisableBehaviorMonitoring: %d\n", val))
		}
		val, _, err = rtpKey.GetIntegerValue("DisableOnAccessProtection")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  DisableOnAccessProtection: %d\n", val))
		}
		val, _, err = rtpKey.GetIntegerValue("DisableScanOnRealtimeEnable")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  DisableScanOnRealtimeEnable: %d\n", val))
		}
		rtpKey.Close()
	} else {
		sb.WriteString("  Real-Time Protection: (registry key not accessible)\n")
	}

	// Defender service status
	defKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender`, registry.READ)
	if err == nil {
		val, _, err := defKey.GetIntegerValue("DisableAntiSpyware")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  DisableAntiSpyware: %d\n", val))
		}
		defKey.Close()
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// defenderExclusions reads all Defender exclusions from the registry.
func defenderExclusions() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Windows Defender Exclusions:\n\n")

	exclusionTypes := []struct {
		name    string
		regPath string
	}{
		{"Path Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`},
		{"Process Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`},
		{"Extension Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`},
	}

	totalExclusions := 0
	for _, et := range exclusionTypes {
		sb.WriteString(fmt.Sprintf("  %s:\n", et.name))
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, et.regPath, registry.READ)
		if err != nil {
			sb.WriteString("    (not accessible or empty)\n")
			continue
		}

		valueNames, err := key.ReadValueNames(-1)
		key.Close()
		if err != nil || len(valueNames) == 0 {
			sb.WriteString("    (none)\n")
			continue
		}

		for _, name := range valueNames {
			sb.WriteString(fmt.Sprintf("    - %s\n", name))
			totalExclusions++
		}
	}

	// Also check policy-based exclusions
	sb.WriteString("\n  Policy-Based Exclusions:\n")
	policyPaths := []struct {
		name    string
		regPath string
	}{
		{"Path", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`},
		{"Process", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes`},
		{"Extension", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions`},
	}

	for _, pp := range policyPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, pp.regPath, registry.READ)
		if err != nil {
			continue
		}
		valueNames, err := key.ReadValueNames(-1)
		key.Close()
		if err != nil || len(valueNames) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("    %s:\n", pp.name))
		for _, name := range valueNames {
			sb.WriteString(fmt.Sprintf("      - %s\n", name))
			totalExclusions++
		}
	}

	sb.WriteString(fmt.Sprintf("\n  Total: %d exclusions\n", totalExclusions))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// defenderAddExclusion adds a path, process, or extension exclusion.
// Uses PowerShell Add-MpPreference cmdlet which works with Tamper Protection.
func defenderAddExclusion(args defenderArgs) structs.CommandResult {
	if args.Value == "" {
		return structs.CommandResult{
			Output:    "Error: value is required (path, process name, or extension)",
			Status:    "error",
			Completed: true,
		}
	}

	exType := strings.ToLower(args.Type)
	if exType == "" {
		exType = "path"
	}

	var paramName string
	switch exType {
	case "path":
		paramName = "ExclusionPath"
	case "process":
		paramName = "ExclusionProcess"
	case "extension":
		paramName = "ExclusionExtension"
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown exclusion type: %s\nAvailable: path, process, extension", exType),
			Status:    "error",
			Completed: true,
		}
	}

	// Use PowerShell Add-MpPreference — works through official Defender API
	// even when Tamper Protection blocks direct registry writes
	psCmd := fmt.Sprintf("Add-MpPreference -%s '%s'", paramName, strings.ReplaceAll(args.Value, "'", "''"))
	output, err := defenderRunPowerShell(psCmd)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding exclusion: %v\n%s\nRequires administrator privileges.", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Added Defender %s exclusion: %s", exType, args.Value),
		Status:    "success",
		Completed: true,
	}
}

// defenderRemoveExclusion removes a path, process, or extension exclusion.
// Uses PowerShell Remove-MpPreference cmdlet which works with Tamper Protection.
func defenderRemoveExclusion(args defenderArgs) structs.CommandResult {
	if args.Value == "" {
		return structs.CommandResult{
			Output:    "Error: value is required (path, process name, or extension)",
			Status:    "error",
			Completed: true,
		}
	}

	exType := strings.ToLower(args.Type)
	if exType == "" {
		exType = "path"
	}

	var paramName string
	switch exType {
	case "path":
		paramName = "ExclusionPath"
	case "process":
		paramName = "ExclusionProcess"
	case "extension":
		paramName = "ExclusionExtension"
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown exclusion type: %s\nAvailable: path, process, extension", exType),
			Status:    "error",
			Completed: true,
		}
	}

	// Use PowerShell Remove-MpPreference — works through official Defender API
	psCmd := fmt.Sprintf("Remove-MpPreference -%s '%s'", paramName, strings.ReplaceAll(args.Value, "'", "''"))
	output, err := defenderRunPowerShell(psCmd)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing exclusion: %v\n%s\nRequires administrator privileges.", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed Defender %s exclusion: %s", exType, args.Value),
		Status:    "success",
		Completed: true,
	}
}

// defenderRunPowerShell runs a PowerShell command for Defender management.
func defenderRunPowerShell(psCmd string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// defenderThreats queries recent threat detections.
func defenderThreats() structs.CommandResult {
	result, err := defenderWMIQueryWithTimeout("SELECT * FROM MSFT_MpThreatDetection", 15*time.Second)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying threats: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if result == "(no results)" {
		return structs.CommandResult{
			Output:    "No recent threat detections found.",
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Recent Threat Detections:\n\n%s", result),
		Status:    "success",
		Completed: true,
	}
}
