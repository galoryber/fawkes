//go:build windows

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type wmiCheckResult struct {
	Host          string `json:"host"`
	RPCPort       string `json:"rpc_port"`
	WMIConnect    string `json:"wmi_connect"`
	WMIQuery      string `json:"wmi_query"`
	ProcessCreate string `json:"process_create"`
	OverallStatus string `json:"overall_status"`
	Recommendation string `json:"recommendation,omitempty"`
}

func wmiCheck(target string, timeout int) structs.CommandResult {
	if target == "" {
		return errorResult("Error: target is required for check action")
	}

	checkTimeout := 10 * time.Second
	if timeout > 0 {
		checkTimeout = time.Duration(timeout) * time.Second
	}

	result := wmiCheckResult{
		Host:          target,
		OverallStatus: "fail",
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout*3)
	defer cancel()

	// Check 1: RPC port (135)
	result.RPCPort = checkTCPPort(ctx, target, "135", checkTimeout)
	if result.RPCPort != "open" {
		result.WMIConnect = "skipped"
		result.WMIQuery = "skipped"
		result.ProcessCreate = "skipped"
		result.Recommendation = "Port 135 (RPC) is not reachable. WMI requires RPC on port 135 + dynamic high ports."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 2: WMI connection via COM
	type connectResult struct {
		conn    *wmiConnection
		cleanup func()
		err     error
	}
	connCh := make(chan connectResult, 1)
	go func() {
		conn, cleanup, err := wmiConnect(target)
		connCh <- connectResult{conn, cleanup, err}
	}()

	var conn *wmiConnection
	var cleanup func()

	select {
	case res := <-connCh:
		if res.err != nil {
			result.WMIConnect = fmt.Sprintf("fail: %v", res.err)
			result.WMIQuery = "skipped"
			result.ProcessCreate = "skipped"
			errStr := res.err.Error()
			if strings.Contains(errStr, "Access is denied") || strings.Contains(errStr, "0x80070005") {
				result.Recommendation = "Access denied — use make-token with admin credentials first."
			} else if strings.Contains(errStr, "RPC server is unavailable") || strings.Contains(errStr, "0x800706BA") {
				result.Recommendation = "RPC server unavailable. WMI/DCOM may be disabled on the target."
			} else {
				result.Recommendation = fmt.Sprintf("WMI connection failed: %v", res.err)
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return successResult(string(data))
		}
		conn = res.conn
		cleanup = res.cleanup
		defer cleanup()
		result.WMIConnect = "pass"
	case <-time.After(checkTimeout):
		result.WMIConnect = "timeout"
		result.WMIQuery = "skipped"
		result.ProcessCreate = "skipped"
		result.Recommendation = "WMI connection timed out. DCOM/RPC may be firewalled."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 3: WMI query capability
	output, err := wmiExecQuery(conn, "SELECT Name, Version FROM Win32_OperatingSystem")
	if err != nil {
		result.WMIQuery = fmt.Sprintf("fail: %v", err)
		result.ProcessCreate = "skipped"
	} else {
		result.WMIQuery = "pass"
		if strings.Contains(output, "Name") {
			osLine := ""
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, "Name") && strings.Contains(line, "=") {
					osLine = strings.TrimSpace(line)
					break
				}
			}
			if osLine != "" {
				result.WMIQuery = fmt.Sprintf("pass (%s)", osLine)
			}
		}

		// Check 4: Win32_Process access (can we query processes = likely can create them)
		procOutput, procErr := wmiExecQuery(conn, "SELECT COUNT(*) FROM Win32_Process")
		if procErr != nil {
			result.ProcessCreate = fmt.Sprintf("query fail: %v — may still be able to create", procErr)
		} else {
			_ = procOutput
			result.ProcessCreate = "pass (Win32_Process accessible)"
		}
	}

	// Determine overall status
	if result.RPCPort == "open" && result.WMIConnect == "pass" && strings.HasPrefix(result.WMIQuery, "pass") {
		result.OverallStatus = "pass"
		result.Recommendation = "Target is ready for WMI lateral movement."
	} else {
		result.Recommendation = "Some prerequisites failed. Review individual check results."
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(data))
}
