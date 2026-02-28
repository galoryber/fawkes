package commands

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

// CredCheckCommand tests credentials against multiple protocols on target hosts.
type CredCheckCommand struct{}

func (c *CredCheckCommand) Name() string { return "cred-check" }
func (c *CredCheckCommand) Description() string {
	return "Test credentials against SMB, WinRM, SSH, LDAP on target hosts"
}

type credCheckArgs struct {
	Hosts    string `json:"hosts"`    // comma-separated IPs or CIDR
	Username string `json:"username"` // DOMAIN\user or user@domain
	Password string `json:"password"` // password
	Hash     string `json:"hash"`     // NTLM hash for PTH (SMB only)
	Domain   string `json:"domain"`   // domain (optional)
	Timeout  int    `json:"timeout"`  // per-check timeout in seconds
}

type credCheckResult struct {
	Host     string
	Protocol string
	Success  bool
	Detail   string
}

func (c *CredCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args credCheckArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hosts == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: -hosts, -username, and -password (or -hash) are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 5
	}
	timeout := time.Duration(args.Timeout) * time.Second

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

	hosts := lateralParseHosts(args.Hosts)
	if len(hosts) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid hosts parsed",
			Status:    "error",
			Completed: true,
		}
	}
	if len(hosts) > 256 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: too many hosts (%d). Maximum 256.", len(hosts)),
			Status:    "error",
			Completed: true,
		}
	}

	// Test each host concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	var allResults []credCheckResult
	sem := make(chan struct{}, 10)

	for _, host := range hosts {
		if task.DidStop() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			if task.DidStop() {
				return
			}

			results := credCheckHost(task, h, args, timeout)
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// Format output
	var sb strings.Builder
	sb.WriteString("=== CREDENTIAL CHECK ===\n")
	sb.WriteString(fmt.Sprintf("User: %s\\%s\n\n", args.Domain, args.Username))

	successCount := 0
	hostResults := make(map[string][]credCheckResult)
	for _, r := range allResults {
		hostResults[r.Host] = append(hostResults[r.Host], r)
		if r.Success {
			successCount++
		}
	}

	for _, host := range hosts {
		results := hostResults[host]
		if len(results) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("--- %s ---\n", host))
		for _, r := range results {
			status := "[-]"
			if r.Success {
				status = "[+]"
			}
			sb.WriteString(fmt.Sprintf("  %s %-12s %s\n", status, r.Protocol, r.Detail))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("--- %d host(s) checked, %d successful auth(s) ---\n", len(hosts), successCount))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func credCheckHost(task structs.Task, host string, args credCheckArgs, timeout time.Duration) []credCheckResult {
	var results []credCheckResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	checks := []struct {
		name string
		fn   func() credCheckResult
	}{
		{"SMB", func() credCheckResult { return credCheckSMB(host, args, timeout) }},
		{"WinRM", func() credCheckResult { return credCheckWinRM(host, args, timeout) }},
		{"LDAP", func() credCheckResult { return credCheckLDAP(host, args, timeout) }},
	}

	for _, check := range checks {
		if task.DidStop() {
			break
		}
		wg.Add(1)
		go func(name string, fn func() credCheckResult) {
			defer wg.Done()
			r := fn()
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(check.name, check.fn)
	}
	wg.Wait()

	return results
}

func credCheckSMB(host string, args credCheckArgs, timeout time.Duration) credCheckResult {
	result := credCheckResult{Host: host, Protocol: "SMB"}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "445"), timeout)
	if err != nil {
		result.Detail = "port closed/unreachable"
		return result
	}

	initiator := &smb2.NTLMInitiator{
		User:   args.Username,
		Domain: args.Domain,
	}
	if args.Hash != "" {
		hashStr := strings.TrimSpace(args.Hash)
		if parts := strings.SplitN(hashStr, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			hashStr = parts[1]
		}
		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil || len(hashBytes) != 16 {
			_ = conn.Close()
			result.Detail = "invalid NTLM hash"
			return result
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
		result.Detail = fmt.Sprintf("auth failed: %v", err)
		return result
	}

	// Try to list shares to confirm access
	_ = conn.SetDeadline(time.Now().Add(timeout))
	shares, _ := session.ListSharenames()
	_ = session.Logoff()
	_ = conn.Close()

	result.Success = true
	result.Detail = fmt.Sprintf("authenticated (%d shares visible)", len(shares))
	return result
}

func credCheckWinRM(host string, args credCheckArgs, timeout time.Duration) credCheckResult {
	result := credCheckResult{Host: host, Protocol: "WinRM"}

	// Check if WinRM port is open first
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "5985"), timeout)
	if err != nil {
		result.Detail = "port 5985 closed/unreachable"
		return result
	}
	_ = conn.Close()

	// Attempt HTTP Basic auth (WinRM accepts NTLM but Basic is simpler to test)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("http://%s:5985/wsman", host)
	req, err := http.NewRequest("POST", url, strings.NewReader(""))
	if err != nil {
		result.Detail = fmt.Sprintf("request error: %v", err)
		return result
	}

	user := args.Username
	if args.Domain != "" {
		user = args.Domain + `\` + args.Username
	}
	req.SetBasicAuth(user, args.Password)
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		result.Detail = fmt.Sprintf("connection error: %v", err)
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		result.Success = true
		result.Detail = "authenticated (HTTP 200)"
	case 401:
		result.Detail = "auth failed (HTTP 401)"
	default:
		result.Detail = fmt.Sprintf("HTTP %d (may need NTLM/Kerberos)", resp.StatusCode)
	}

	return result
}

func credCheckLDAP(host string, args credCheckArgs, timeout time.Duration) credCheckResult {
	result := credCheckResult{Host: host, Protocol: "LDAP"}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "389"), timeout)
	if err != nil {
		result.Detail = "port 389 closed/unreachable"
		return result
	}
	_ = conn.Close()

	// LDAP simple bind test — construct a minimal bind request
	bindDN := args.Username
	if args.Domain != "" {
		bindDN = args.Username + "@" + args.Domain
	}

	ldapConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "389"), timeout)
	if err != nil {
		result.Detail = "LDAP connect failed"
		return result
	}
	defer ldapConn.Close()
	_ = ldapConn.SetDeadline(time.Now().Add(timeout))

	// Build LDAP Simple Bind Request (ASN.1/BER encoded)
	bindReq := credCheckBuildLDAPBind(1, bindDN, args.Password)
	_, err = ldapConn.Write(bindReq)
	if err != nil {
		result.Detail = fmt.Sprintf("LDAP write error: %v", err)
		return result
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := ldapConn.Read(buf)
	if err != nil {
		result.Detail = fmt.Sprintf("LDAP read error: %v", err)
		return result
	}

	// Parse minimal LDAP bind response — look for resultCode
	resultCode := credCheckParseLDAPBindResponse(buf[:n])
	switch resultCode {
	case 0: // success
		result.Success = true
		result.Detail = "authenticated (LDAP bind success)"
	case 49: // invalidCredentials
		result.Detail = "auth failed (invalid credentials)"
	case 53: // unwillingToPerform
		result.Detail = "auth denied (account locked/disabled)"
	default:
		result.Detail = fmt.Sprintf("LDAP result code %d", resultCode)
	}

	return result
}

// credCheckBuildLDAPBind constructs a minimal LDAP BindRequest (Simple auth).
func credCheckBuildLDAPBind(messageID int, bindDN, password string) []byte {
	// BindRequest ::= [APPLICATION 0] SEQUENCE {
	//   version INTEGER (3),
	//   name LDAPDN,
	//   authentication AuthenticationChoice { simple [0] OCTET STRING }
	// }

	// Encode version (INTEGER 3)
	version := []byte{0x02, 0x01, 0x03}
	// Encode bindDN (OCTET STRING)
	dnBytes := credCheckBERString(0x04, bindDN)
	// Encode password (context [0] OCTET STRING — simple auth)
	passBytes := credCheckBERString(0x80, password)

	// BindRequest [APPLICATION 0]
	bindBody := append(version, dnBytes...)
	bindBody = append(bindBody, passBytes...)
	bindReq := credCheckBERWrap(0x60, bindBody)

	// Message ID (INTEGER)
	msgID := []byte{0x02, 0x01, byte(messageID)}

	// LDAPMessage SEQUENCE
	msgBody := append(msgID, bindReq...)
	return credCheckBERWrap(0x30, msgBody)
}

func credCheckBERString(tag byte, s string) []byte {
	data := []byte(s)
	return credCheckBERWrap(tag, data)
}

func credCheckBERWrap(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	}
	// Long form length
	lenBytes := credCheckBEREncodeLength(length)
	header := append([]byte{tag}, lenBytes...)
	return append(header, data...)
}

func credCheckBEREncodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var buf []byte
	for length > 0 {
		buf = append([]byte{byte(length & 0xff)}, buf...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

// credCheckParseLDAPBindResponse extracts the resultCode from an LDAP BindResponse.
func credCheckParseLDAPBindResponse(data []byte) int {
	// Minimal parsing: LDAPMessage -> SEQUENCE -> messageID -> BindResponse -> resultCode
	if len(data) < 10 {
		return -1
	}

	// Skip outer SEQUENCE tag + length
	pos := 0
	if data[pos] != 0x30 {
		return -1
	}
	pos++
	_, skip := credCheckBERDecodeLength(data[pos:])
	pos += skip

	// Skip messageID (INTEGER)
	if data[pos] != 0x02 {
		return -1
	}
	pos++
	idLen, skip := credCheckBERDecodeLength(data[pos:])
	pos += skip + idLen

	// BindResponse [APPLICATION 1]
	if pos >= len(data) || data[pos] != 0x61 {
		return -1
	}
	pos++
	_, skip = credCheckBERDecodeLength(data[pos:])
	pos += skip

	// resultCode (ENUMERATED)
	if pos >= len(data) || data[pos] != 0x0a {
		return -1
	}
	pos++
	rcLen, skip := credCheckBERDecodeLength(data[pos:])
	pos += skip
	if pos+rcLen > len(data) || rcLen == 0 {
		return -1
	}
	return int(data[pos])
}

func credCheckBERDecodeLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 128 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes+1 > len(data) {
		return 0, 1
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(data[i])
	}
	return length, numBytes + 1
}
