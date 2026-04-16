//go:build windows

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc/mgr"
)

type psexecCheckResult struct {
	Host           string `json:"host"`
	SMBPort        string `json:"smb_port"`
	SCMAccess      string `json:"scm_access"`
	ServiceCreate  string `json:"service_create"`
	AdminShareC    string `json:"admin_share_c"`
	AdminShareADM  string `json:"admin_share_admin"`
	OverallStatus  string `json:"overall_status"`
	Recommendation string `json:"recommendation,omitempty"`
}

func psexecCheck(host string, timeout int) structs.CommandResult {
	if host == "" {
		return errorResult("Error: host is required for check action")
	}

	checkTimeout := 10 * time.Second
	if timeout > 0 {
		checkTimeout = time.Duration(timeout) * time.Second
	}

	result := psexecCheckResult{
		Host:          host,
		OverallStatus: "fail",
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout*3)
	defer cancel()

	// Check 1: SMB port (445)
	result.SMBPort = checkTCPPort(ctx, host, "445", checkTimeout)
	if result.SMBPort != "open" {
		result.Recommendation = "Port 445 is not reachable. SMB/PSExec requires port 445."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 2: SCM access via mgr.ConnectRemote
	type scmResult struct {
		m   *mgr.Mgr
		err error
	}
	scmCh := make(chan scmResult, 1)
	go func() {
		m, err := mgr.ConnectRemote(host)
		scmCh <- scmResult{m, err}
	}()

	select {
	case res := <-scmCh:
		if res.err != nil {
			result.SCMAccess = fmt.Sprintf("fail: %v", res.err)
			result.ServiceCreate = "skipped"
			result.AdminShareC = "skipped"
			result.AdminShareADM = "skipped"
			if strings.Contains(res.err.Error(), "Access is denied") {
				result.Recommendation = "Access denied — use make-token with admin credentials first."
			} else {
				result.Recommendation = fmt.Sprintf("SCM connection failed: %v", res.err)
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return successResult(string(data))
		}
		result.SCMAccess = "pass"
		defer res.m.Disconnect()

		// Check 3: Service enumeration (validates admin access)
		svcs, err := res.m.ListServices()
		if err != nil {
			result.ServiceCreate = fmt.Sprintf("fail: cannot list services: %v", err)
		} else {
			result.ServiceCreate = fmt.Sprintf("pass (%d services visible)", len(svcs))
		}
	case <-time.After(checkTimeout):
		result.SCMAccess = "timeout"
		result.ServiceCreate = "skipped"
		result.AdminShareC = "skipped"
		result.AdminShareADM = "skipped"
		result.Recommendation = "SCM connection timed out. Host may be firewalled or not a Windows machine."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 4: Admin share access (C$ and ADMIN$)
	result.AdminShareC = checkSMBShare(ctx, host, "C$", checkTimeout)
	result.AdminShareADM = checkSMBShare(ctx, host, "ADMIN$", checkTimeout)

	// Determine overall status
	if result.SMBPort == "open" && result.SCMAccess == "pass" && strings.HasPrefix(result.ServiceCreate, "pass") {
		result.OverallStatus = "pass"
		result.Recommendation = "Target is ready for psexec lateral movement."
	} else {
		result.Recommendation = "Some prerequisites failed. Review individual check results."
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(data))
}

// checkTCPPort tests if a TCP port is reachable.
func checkTCPPort(ctx context.Context, host, port string, timeout time.Duration) string {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		if isTimeout(err) {
			return "timeout"
		}
		return fmt.Sprintf("closed: %v", err)
	}
	conn.Close()
	return "open"
}

// checkSMBShare reports admin share accessibility based on SCM access.
func checkSMBShare(_ context.Context, host, share string, _ time.Duration) string {
	// Direct share access check would require go-smb2 and explicit credentials.
	// Since SCM access (which we already verified) requires admin,
	// admin shares (C$, ADMIN$) are accessible under the same token.
	_ = host
	_ = share
	return "likely accessible (SCM confirmed admin)"
}
