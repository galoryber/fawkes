package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

type sshCheckResult struct {
	Host           string `json:"host"`
	SSHPort        string `json:"ssh_port"`
	Banner         string `json:"banner,omitempty"`
	Authentication string `json:"authentication"`
	ShellAccess    string `json:"shell_access"`
	OverallStatus  string `json:"overall_status"`
	Recommendation string `json:"recommendation,omitempty"`
}

func sshExecCheck(args sshExecArgs) structs.CommandResult {
	if args.Host == "" {
		return errorResult("Error: host is required for check action")
	}

	port := args.Port
	if port <= 0 {
		port = 22
	}

	checkTimeout := 10 * time.Second
	if args.Timeout > 0 {
		checkTimeout = time.Duration(args.Timeout) * time.Second
	}

	result := sshCheckResult{
		Host:          args.Host,
		OverallStatus: "fail",
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout*3)
	defer cancel()

	// Check 1: SSH port
	portStr := fmt.Sprintf("%d", port)
	result.SSHPort = checkTCPPort(ctx, args.Host, portStr, checkTimeout)
	if result.SSHPort != "open" {
		result.Authentication = "skipped"
		result.ShellAccess = "skipped"
		result.Recommendation = fmt.Sprintf("Port %d is not reachable. SSH requires port %d.", port, port)
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Check 1b: Grab SSH banner
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(args.Host, portStr), checkTimeout)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			result.Banner = strings.TrimSpace(string(buf[:n]))
		}
		conn.Close()
	}

	// Check 2: Authentication (if credentials provided)
	if args.Username == "" || (args.Password == "" && args.KeyPath == "" && args.KeyData == "") {
		result.Authentication = "skipped (no credentials provided)"
		result.ShellAccess = "skipped"
		result.OverallStatus = "partial"
		result.Recommendation = "Port reachable. Provide credentials to test authentication."
		data, _ := json.MarshalIndent(result, "", "  ")
		return successResult(string(data))
	}

	// Build SSH auth methods
	var authMethods []ssh.AuthMethod
	if args.Password != "" {
		authMethods = append(authMethods, ssh.Password(args.Password))
	}
	if args.KeyData != "" {
		signer, err := ssh.ParsePrivateKey([]byte(args.KeyData))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			result.Authentication = fmt.Sprintf("fail: invalid key data: %v", err)
			result.ShellAccess = "skipped"
			data, _ := json.MarshalIndent(result, "", "  ")
			return successResult(string(data))
		}
	}

	config := &ssh.ClientConfig{
		User:            args.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         checkTimeout,
	}

	type sshResult struct {
		client *ssh.Client
		err    error
	}
	ch := make(chan sshResult, 1)
	go func() {
		client, err := ssh.Dial("tcp", net.JoinHostPort(args.Host, portStr), config)
		ch <- sshResult{client, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			errStr := res.err.Error()
			if strings.Contains(errStr, "unable to authenticate") || strings.Contains(errStr, "no supported methods") {
				result.Authentication = "fail: invalid credentials"
				result.ShellAccess = "skipped"
				result.Recommendation = "Authentication failed. Check username/password/key."
			} else {
				result.Authentication = fmt.Sprintf("fail: %v", res.err)
				result.ShellAccess = "skipped"
				result.Recommendation = fmt.Sprintf("SSH connection failed: %v", res.err)
			}
		} else {
			defer res.client.Close()
			result.Authentication = "pass"

			// Check 3: Shell access
			session, err := res.client.NewSession()
			if err != nil {
				result.ShellAccess = fmt.Sprintf("fail: %v", err)
			} else {
				out, err := session.CombinedOutput("id 2>/dev/null || whoami")
				session.Close()
				if err != nil {
					result.ShellAccess = fmt.Sprintf("fail: %v", err)
				} else {
					userInfo := strings.TrimSpace(string(out))
					result.ShellAccess = fmt.Sprintf("pass (%s)", userInfo)
					result.OverallStatus = "pass"
					result.Recommendation = "Target is ready for SSH lateral movement."
				}
			}
		}
	case <-ctx.Done():
		result.Authentication = "timeout"
		result.ShellAccess = "skipped"
		result.Recommendation = "SSH authentication timed out."
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(data))
}
