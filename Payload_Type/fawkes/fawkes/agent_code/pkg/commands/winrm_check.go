package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/masterzen/winrm"
)

type winrmCheckResult struct {
	Host           string `json:"host"`
	WinRMHTTP      string `json:"winrm_http"`
	WinRMHTTPS     string `json:"winrm_https"`
	Authentication string `json:"authentication"`
	ShellCreate    string `json:"shell_create"`
	OverallStatus  string `json:"overall_status"`
	Recommendation string `json:"recommendation,omitempty"`
}

func winrmCheck(args winrmArgs) structs.CommandResult {
	if args.Host == "" {
		return errorResult("Error: host is required for check action")
	}

	checkTimeout := 10 * time.Second
	if args.Timeout > 0 {
		checkTimeout = time.Duration(args.Timeout) * time.Second
	}

	result := winrmCheckResult{
		Host:          args.Host,
		OverallStatus: "fail",
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout*3)
	defer cancel()

	// Check 1: WinRM HTTP port (5985)
	result.WinRMHTTP = checkTCPPort(ctx, args.Host, "5985", checkTimeout)

	// Check 2: WinRM HTTPS port (5986)
	result.WinRMHTTPS = checkTCPPort(ctx, args.Host, "5986", checkTimeout)

	if result.WinRMHTTP != "open" && result.WinRMHTTPS != "open" {
		result.Authentication = "skipped"
		result.ShellCreate = "skipped"
		result.Recommendation = "Neither WinRM port (5985/5986) is reachable. WinRM may be disabled."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 3: Authentication (if credentials provided)
	if args.Username == "" || (args.Password == "" && args.Hash == "") {
		result.Authentication = "skipped (no credentials provided)"
		result.ShellCreate = "skipped"
		result.OverallStatus = "partial"
		result.Recommendation = "Ports reachable. Provide credentials to test authentication."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	port := args.Port
	useTLS := args.UseTLS
	if port <= 0 {
		if result.WinRMHTTPS == "open" {
			port = 5986
			useTLS = true
		} else {
			port = 5985
			useTLS = false
		}
	}

	endpoint := winrm.NewEndpoint(args.Host, port, useTLS, true, nil, nil, nil, checkTimeout)
	authCred := args.Password
	if args.Hash != "" {
		authCred = args.Hash
	}

	params := winrm.DefaultParameters
	if args.Hash != "" {
		params.TransportDecorator = func() winrm.Transporter {
			return &winrmHashTransport{
				username: args.Username,
				hash:     args.Hash,
				insecure: true,
				useTLS:   useTLS,
				timeout:  checkTimeout,
			}
		}
	} else {
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
	}

	client, err := winrm.NewClientWithParameters(endpoint, args.Username, authCred, params)
	if err != nil {
		result.Authentication = fmt.Sprintf("fail: %v", err)
		result.ShellCreate = "skipped"
		result.Recommendation = fmt.Sprintf("WinRM client creation failed: %v", err)
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Try a lightweight command to test auth + shell creation
	type shellResult struct {
		stdout string
		err    error
	}
	ch := make(chan shellResult, 1)
	go func() {
		stdout, _, _, err := client.RunWithString("hostname", "")
		ch <- shellResult{stdout, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			errStr := res.err.Error()
			if strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized") {
				result.Authentication = "fail: invalid credentials (401)"
				result.ShellCreate = "skipped"
				result.Recommendation = "Authentication failed. Check username/password/hash."
			} else if strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
				result.Authentication = "pass (credentials accepted)"
				result.ShellCreate = "fail: forbidden (user may lack WinRM access)"
				result.Recommendation = "User authenticated but lacks WinRM permissions."
			} else {
				result.Authentication = fmt.Sprintf("fail: %v", res.err)
				result.ShellCreate = "skipped"
				result.Recommendation = fmt.Sprintf("WinRM connection failed: %v", res.err)
			}
		} else {
			hostname := strings.TrimSpace(res.stdout)
			result.Authentication = "pass"
			result.ShellCreate = fmt.Sprintf("pass (hostname: %s)", hostname)
			result.OverallStatus = "pass"
			result.Recommendation = "Target is ready for WinRM lateral movement."
		}
	case <-time.After(checkTimeout):
		result.Authentication = "timeout"
		result.ShellCreate = "skipped"
		result.Recommendation = "WinRM authentication timed out."
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(data))
}
