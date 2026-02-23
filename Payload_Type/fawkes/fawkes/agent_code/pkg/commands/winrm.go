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

type WinrmCommand struct{}

func (c *WinrmCommand) Name() string { return "winrm" }
func (c *WinrmCommand) Description() string {
	return "Execute commands on remote Windows hosts via WinRM (T1021.006)"
}

type winrmArgs struct {
	Host     string `json:"host"`     // target host IP or hostname
	Username string `json:"username"` // username for auth (DOMAIN\user or user)
	Password string `json:"password"` // password for auth
	Command  string `json:"command"`  // command to execute
	Port     int    `json:"port"`     // WinRM port (default: 5985)
	UseTLS   bool   `json:"use_tls"`  // use HTTPS (port 5986)
	Shell    string `json:"shell"`    // "cmd" (default) or "powershell"
	Timeout  int    `json:"timeout"`  // command timeout in seconds (default: 60)
}

func (c *WinrmCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -host <target> -username <user> -password <pass> -command <cmd>",
			Status:    "error",
			Completed: true,
		}
	}

	var args winrmArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Host == "" || args.Username == "" || args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: host, username, and password are required",
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

	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 5986
		} else {
			args.Port = 5985
		}
	}

	if args.Shell == "" {
		args.Shell = "cmd"
	}

	if args.Timeout <= 0 {
		args.Timeout = 60
	}

	endpoint := winrm.NewEndpoint(
		args.Host,
		args.Port,
		args.UseTLS,
		true, // insecure: skip cert verification for self-signed certs
		nil, nil, nil,
		time.Duration(args.Timeout)*time.Second,
	)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientNTLM{}
	}

	client, err := winrm.NewClientWithParameters(endpoint, args.Username, args.Password, params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating WinRM client: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	var stdout, stderr string
	var exitCode int

	switch args.Shell {
	case "powershell", "ps":
		stdout, stderr, exitCode, err = client.RunPSWithContextWithString(ctx, args.Command, "")
	default:
		stdout, stderr, exitCode, err = client.RunWithContextWithString(ctx, args.Command, "")
	}

	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing command on %s: %v", args.Host, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] WinRM %s@%s:%d (%s)\n", args.Username, args.Host, args.Port, args.Shell))
	sb.WriteString(fmt.Sprintf("[*] Command: %s\n", args.Command))
	sb.WriteString(fmt.Sprintf("[*] Exit Code: %d\n", exitCode))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	if stdout != "" {
		sb.WriteString(stdout)
		if !strings.HasSuffix(stdout, "\n") {
			sb.WriteString("\n")
		}
	}

	if stderr != "" {
		sb.WriteString("[STDERR]\n")
		sb.WriteString(stderr)
		if !strings.HasSuffix(stderr, "\n") {
			sb.WriteString("\n")
		}
	}

	status := "success"
	if exitCode != 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}
