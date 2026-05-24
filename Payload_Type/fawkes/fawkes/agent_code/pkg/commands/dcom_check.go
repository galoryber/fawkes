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

type dcomCheckResult struct {
	Host          string `json:"host"`
	RPCPort       string `json:"rpc_port"`
	DCOMConnect   string `json:"dcom_connect"`
	ObjectAccess  string `json:"object_access"`
	OverallStatus string `json:"overall_status"`
	Recommendation string `json:"recommendation,omitempty"`
}

func dcomCheck(host string, timeout int) structs.CommandResult {
	if host == "" {
		return errorResult("Error: host is required for check action")
	}

	checkTimeout := 10 * time.Second
	if timeout > 0 {
		checkTimeout = time.Duration(timeout) * time.Second
	}

	result := dcomCheckResult{
		Host:          host,
		OverallStatus: "fail",
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout*3)
	defer cancel()

	// Check 1: RPC port (135)
	result.RPCPort = checkTCPPort(ctx, host, "135", checkTimeout)
	if result.RPCPort != "open" {
		result.DCOMConnect = "skipped"
		result.ObjectAccess = "skipped"
		result.Recommendation = "Port 135 (RPC) is not reachable. DCOM requires RPC on port 135 + dynamic high ports."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 2: DCOM connectivity via WMI (uses same COM infrastructure)
	type connectResult struct {
		conn    *wmiConnection
		cleanup func()
		err     error
	}
	connCh := make(chan connectResult, 1)
	go func() {
		conn, cleanup, err := wmiConnect(host)
		connCh <- connectResult{conn, cleanup, err}
	}()

	select {
	case res := <-connCh:
		if res.err != nil {
			result.DCOMConnect = fmt.Sprintf("fail: %v", res.err)
			result.ObjectAccess = "skipped"
			errStr := res.err.Error()
			if strings.Contains(errStr, "Access is denied") || strings.Contains(errStr, "0x80070005") {
				result.Recommendation = "Access denied — use make-token with admin credentials first."
			} else if strings.Contains(errStr, "RPC server is unavailable") {
				result.Recommendation = "DCOM/RPC unavailable on target. May be disabled or firewalled."
			} else {
				result.Recommendation = fmt.Sprintf("DCOM connection failed: %v", res.err)
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return successResult(string(data))
		}
		result.DCOMConnect = "pass (WMI/DCOM accessible)"
		defer res.cleanup()

		// Check 3: Query capability confirms COM object instantiation works
		_, err := wmiExecQuery(res.conn, "SELECT Name FROM Win32_OperatingSystem")
		if err != nil {
			result.ObjectAccess = fmt.Sprintf("limited: %v", err)
		} else {
			result.ObjectAccess = "pass"
		}
	case <-time.After(checkTimeout):
		result.DCOMConnect = "timeout"
		result.ObjectAccess = "skipped"
		result.Recommendation = "DCOM connection timed out. Host may be firewalled."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	if result.RPCPort == "open" && strings.HasPrefix(result.DCOMConnect, "pass") {
		result.OverallStatus = "pass"
		result.Recommendation = "Target is ready for DCOM lateral movement."
	} else {
		result.Recommendation = "Some prerequisites failed. Review individual check results."
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(data))
}
