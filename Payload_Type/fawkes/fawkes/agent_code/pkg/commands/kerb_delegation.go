package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type KerbDelegationCommand struct{}

func (c *KerbDelegationCommand) Name() string        { return "kerb-delegation" }
func (c *KerbDelegationCommand) Description() string { return "Enumerate Kerberos delegation relationships in Active Directory" }

type kerbDelegArgs struct {
	Action   string `json:"action"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`
}

// userAccountControl flags
const (
	uacTrustedForDelegation        = 0x80000  // Unconstrained delegation
	uacTrustedToAuthForDelegation  = 0x1000000 // Protocol transition (S4U2Self)
	uacNotDelegated                = 0x100000  // Account is sensitive and cannot be delegated
	uacAccountDisable              = 0x2
)

func (c *KerbDelegationCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <unconstrained|constrained|rbcd|all> -server <DC>",
			Status:    "error",
			Completed: true,
		}
	}

	var args kerbDelegArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: server parameter required (domain controller IP or hostname)",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	conn, err := kdConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	if err := kdBind(conn, args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	baseDN, err := kdDetectBaseDN(conn)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error detecting base DN: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "unconstrained":
		return kdFindUnconstrained(conn, baseDN)
	case "constrained":
		return kdFindConstrained(conn, baseDN)
	case "rbcd":
		return kdFindRBCD(conn, baseDN)
	case "all":
		return kdFindAll(conn, baseDN)
	default:
		return structs.CommandResult{
			Output:    "Error: action must be one of: unconstrained, constrained, rbcd, all",
			Status:    "error",
			Completed: true,
		}
	}
}

func kdConnect(args kerbDelegArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func kdBind(conn *ldap.Conn, args kerbDelegArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	return conn.UnauthenticatedBind("")
}

func kdDetectBaseDN(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entries returned")
	}
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("could not detect defaultNamingContext")
	}
	return baseDN, nil
}

// kdFindUnconstrained finds accounts with TRUSTED_FOR_DELEGATION (excluding DCs)
func kdFindUnconstrained(conn *ldap.Conn, baseDN string) structs.CommandResult {
	// TRUSTED_FOR_DELEGATION = 0x80000 (524288)
	filter := fmt.Sprintf("(&(userAccountControl:1.2.840.113556.1.4.803:=%d)(!(primaryGroupID=516)))", uacTrustedForDelegation)

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "userAccountControl", "objectClass", "servicePrincipalName", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error searching for unconstrained delegation: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Unconstrained Delegation (%d found, excluding DCs)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString("Accounts with TrustedForDelegation can impersonate ANY user to ANY service.\n\n")

	for i, entry := range result.Entries {
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, entry.GetAttributeValue("sAMAccountName")))
		if dns := entry.GetAttributeValue("dNSHostName"); dns != "" {
			sb.WriteString(fmt.Sprintf("    DNS: %s\n", dns))
		}
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		sb.WriteString(fmt.Sprintf("    UAC: 0x%X", uac))
		if uac&uacAccountDisable != 0 {
			sb.WriteString(" [DISABLED]")
		}
		if uac&uacTrustedToAuthForDelegation != 0 {
			sb.WriteString(" [S4U2Self]")
		}
		sb.WriteString("\n")
		if spns := entry.GetAttributeValues("servicePrincipalName"); len(spns) > 0 {
			sb.WriteString(fmt.Sprintf("    SPNs: %s\n", strings.Join(spns[:minInt(3, len(spns))], ", ")))
			if len(spns) > 3 {
				sb.WriteString(fmt.Sprintf("          ...and %d more\n", len(spns)-3))
			}
		}
		if desc := entry.GetAttributeValue("description"); desc != "" {
			sb.WriteString(fmt.Sprintf("    Desc: %s\n", desc))
		}
	}

	if len(result.Entries) == 0 {
		sb.WriteString("No non-DC accounts with unconstrained delegation found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n[!] %d account(s) can capture TGTs from any authenticating user.\n", len(result.Entries)))
		sb.WriteString("    Compromise any of these to escalate via TGT capture.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// kdFindConstrained finds accounts with msDS-AllowedToDelegateTo set
func kdFindConstrained(conn *ldap.Conn, baseDN string) structs.CommandResult {
	filter := "(msDS-AllowedToDelegateTo=*)"

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "msDS-AllowedToDelegateTo", "userAccountControl", "servicePrincipalName", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error searching for constrained delegation: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Constrained Delegation (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString("Accounts that can impersonate users to specific services.\n\n")

	for i, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		delegTo := entry.GetAttributeValues("msDS-AllowedToDelegateTo")

		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, name))
		if dns := entry.GetAttributeValue("dNSHostName"); dns != "" {
			sb.WriteString(fmt.Sprintf("    DNS: %s\n", dns))
		}

		// Protocol transition check
		if uac&uacTrustedToAuthForDelegation != 0 {
			sb.WriteString("    Mode: Constrained with Protocol Transition (S4U2Self + S4U2Proxy)\n")
			sb.WriteString("    [!] Can impersonate ANY user without their interaction\n")
		} else {
			sb.WriteString("    Mode: Constrained (S4U2Proxy only)\n")
			sb.WriteString("    Requires user to authenticate to this service first\n")
		}

		sb.WriteString("    Allowed to delegate to:\n")
		for _, target := range delegTo {
			sb.WriteString(fmt.Sprintf("      - %s\n", target))
		}

		if uac&uacAccountDisable != 0 {
			sb.WriteString("    [DISABLED]\n")
		}
	}

	if len(result.Entries) == 0 {
		sb.WriteString("No accounts with constrained delegation found.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// kdFindRBCD finds objects with msDS-AllowedToActOnBehalfOfOtherIdentity set
func kdFindRBCD(conn *ldap.Conn, baseDN string) structs.CommandResult {
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "userAccountControl", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error searching for RBCD: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Resource-Based Constrained Delegation (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString("Objects where other accounts can impersonate users to their services.\n\n")

	for i, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, name))
		if dns := entry.GetAttributeValue("dNSHostName"); dns != "" {
			sb.WriteString(fmt.Sprintf("    DNS: %s\n", dns))
		}

		// Parse the SD in msDS-AllowedToActOnBehalfOfOtherIdentity to find allowed SIDs
		sdBytes := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		if len(sdBytes) > 0 {
			aces := adcsParseSD(sdBytes)
			sb.WriteString("    Allowed to act on behalf:\n")
			for _, ace := range aces {
				sb.WriteString(fmt.Sprintf("      - %s (mask: 0x%X)\n", ace.sid, ace.mask))
			}
			if len(aces) == 0 {
				sb.WriteString("      (could not parse allowed identities)\n")
			}
		}
	}

	if len(result.Entries) == 0 {
		sb.WriteString("No RBCD configurations found.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// kdFindAll runs all delegation checks and produces a combined report
func kdFindAll(conn *ldap.Conn, baseDN string) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Kerberos Delegation Report\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Unconstrained
	r1 := kdFindUnconstrained(conn, baseDN)
	sb.WriteString(r1.Output)
	sb.WriteString("\n")

	// Constrained
	r2 := kdFindConstrained(conn, baseDN)
	sb.WriteString(r2.Output)
	sb.WriteString("\n")

	// RBCD
	r3 := kdFindRBCD(conn, baseDN)
	sb.WriteString(r3.Output)
	sb.WriteString("\n")

	// Sensitive accounts (NOT_DELEGATED flag)
	filter := fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", uacNotDelegated)
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName"}, nil)
	result, err := conn.SearchWithPaging(req, 100)
	if err == nil && len(result.Entries) > 0 {
		sb.WriteString(fmt.Sprintf("Protected Accounts (NOT_DELEGATED) — %d found\n", len(result.Entries)))
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, entry := range result.Entries {
			sb.WriteString(fmt.Sprintf("  - %s\n", entry.GetAttributeValue("sAMAccountName")))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
