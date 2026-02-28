package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

type SshExecCommand struct{}

func (c *SshExecCommand) Name() string { return "ssh" }
func (c *SshExecCommand) Description() string {
	return "Execute commands on remote hosts via SSH (T1021.004)"
}

type sshExecArgs struct {
	Host     string `json:"host"`     // target host IP or hostname
	Username string `json:"username"` // username for auth
	Password string `json:"password"` // password for auth (optional if key provided)
	KeyPath  string `json:"key_path"` // path to SSH private key on agent's filesystem
	KeyData  string `json:"key_data"` // inline SSH private key (PEM format)
	Command  string `json:"command"`  // command to execute
	Port     int    `json:"port"`     // SSH port (default: 22)
	Timeout  int    `json:"timeout"`  // connection+command timeout in seconds (default: 60)
}

func (c *SshExecCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -host <target> -username <user> [-password <pass> | -key_path <path>] -command <cmd>",
			Status:    "error",
			Completed: true,
		}
	}

	var args sshExecArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Host == "" || args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: host and username are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Command == "" {
		return structs.CommandResult{
			Output:    "Error: command is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Password == "" && args.KeyPath == "" && args.KeyData == "" {
		return structs.CommandResult{
			Output:    "Error: at least one auth method required (password, key_path, or key_data)",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Port <= 0 {
		args.Port = 22
	}

	if args.Timeout <= 0 {
		args.Timeout = 60
	}

	// Build auth methods
	var authMethods []ssh.AuthMethod

	// Key-based auth (try first — preferred)
	if args.KeyData != "" {
		signer, err := parsePrivateKey([]byte(args.KeyData), args.Password)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing inline key: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if args.KeyPath != "" {
		keyBytes, err := os.ReadFile(args.KeyPath)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading key file %s: %v", args.KeyPath, err),
				Status:    "error",
				Completed: true,
			}
		}
		signer, err := parsePrivateKey(keyBytes, args.Password)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing key file %s: %v", args.KeyPath, err),
				Status:    "error",
				Completed: true,
			}
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Password auth (fallback) — try both password and keyboard-interactive
	if args.Password != "" {
		authMethods = append(authMethods, ssh.Password(args.Password))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = args.Password
				}
				return answers, nil
			},
		))
	}

	config := &ssh.ClientConfig{
		User:            args.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // red team tool — host key verification not needed
		Timeout:         time.Duration(args.Timeout) * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", args.Host, args.Port)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	// Connect with context-aware dialer
	client, err := sshDialContext(ctx, "tcp", addr, config)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to %s: %v", addr, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating SSH session on %s: %v", addr, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer session.Close()

	// Execute command with timeout
	type cmdResult struct {
		output []byte
		err    error
	}
	resultCh := make(chan cmdResult, 1)
	go func() {
		out, err := session.CombinedOutput(args.Command)
		resultCh <- cmdResult{out, err}
	}()

	select {
	case res := <-resultCh:
		return formatSSHResult(args, addr, res.output, res.err)
	case <-ctx.Done():
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: command execution on %s timed out after %ds", addr, args.Timeout),
			Status:    "error",
			Completed: true,
		}
	}
}

// parsePrivateKey parses a PEM-encoded SSH private key, optionally with a passphrase.
func parsePrivateKey(pemBytes []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(pemBytes)
}

// formatSSHResult formats the SSH command output for display.
func formatSSHResult(args sshExecArgs, addr string, output []byte, cmdErr error) structs.CommandResult {
	var sb strings.Builder

	authMethod := "password"
	if args.KeyPath != "" {
		authMethod = "key:" + args.KeyPath
	} else if args.KeyData != "" {
		authMethod = "key:inline"
	}

	sb.WriteString(fmt.Sprintf("[*] SSH %s@%s (auth: %s)\n", args.Username, addr, authMethod))
	sb.WriteString(fmt.Sprintf("[*] Command: %s\n", args.Command))

	if cmdErr != nil {
		// Check if it's an ExitError (non-zero exit code)
		if exitErr, ok := cmdErr.(*ssh.ExitError); ok {
			sb.WriteString(fmt.Sprintf("[*] Exit Code: %d\n", exitErr.ExitStatus()))
		} else if _, ok := cmdErr.(*ssh.ExitMissingError); ok {
			sb.WriteString("[*] Exit Code: unknown (session closed without exit status)\n")
		} else {
			sb.WriteString(fmt.Sprintf("[*] Error: %v\n", cmdErr))
		}
	} else {
		sb.WriteString("[*] Exit Code: 0\n")
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")

	if len(output) > 0 {
		sb.Write(output)
		if !strings.HasSuffix(string(output), "\n") {
			sb.WriteString("\n")
		}
	}

	// Non-zero exit still returns output — mark as success if we got output
	status := "success"
	if cmdErr != nil {
		if _, ok := cmdErr.(*ssh.ExitError); !ok {
			// Real connection/session error, not just non-zero exit
			if _, ok2 := cmdErr.(*ssh.ExitMissingError); !ok2 {
				status = "error"
			}
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

// sshDialContext wraps ssh.Dial with context support for cancellation.
func sshDialContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: config.Timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}
