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

func (c *KerbDelegationCommand) Name() string { return "kerb-delegation" }
func (c *KerbDelegationCommand) Description() string {
	return "Enumerate Kerberos delegation relationships in Active Directory"
}

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
	uacTrustedForDelegation       = 0x80000   // Unconstrained delegation
	uacTrustedToAuthForDelegation = 0x1000000 // Protocol transition (S4U2Self)
	uacNotDelegated               = 0x100000  // Account is sensitive and cannot be delegated
	uacAccountDisable             = 0x2
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

// kdOutputEntry is a JSON-serializable delegation entry for browser script rendering.
type kdOutputEntry struct {
	Account        string   `json:"account"`
	DNS            string   `json:"dns,omitempty"`
	DelegationType string   `json:"delegation_type"`
	Mode           string   `json:"mode,omitempty"`
	Targets        []string `json:"targets,omitempty"`
	Disabled       bool     `json:"disabled,omitempty"`
	S4U2Self       bool     `json:"s4u2self,omitempty"`
	SPNs           []string `json:"spns,omitempty"`
	Description    string   `json:"description,omitempty"`
	Risk           string   `json:"risk,omitempty"`
}

func kdMarshalResult(entries []kdOutputEntry) structs.CommandResult {
	if entries == nil {
		entries = []kdOutputEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error marshaling output: %v", err), Status: "error", Completed: true,
		}
	}
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// kdFindUnconstrained finds accounts with TRUSTED_FOR_DELEGATION (excluding DCs)
func kdFindUnconstrained(conn *ldap.Conn, baseDN string) structs.CommandResult {
	entries, err := kdUnconstrainedEntries(conn, baseDN)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error searching for unconstrained delegation: %v", err), Status: "error", Completed: true}
	}
	return kdMarshalResult(entries)
}

func kdUnconstrainedEntries(conn *ldap.Conn, baseDN string) ([]kdOutputEntry, error) {
	filter := fmt.Sprintf("(&(userAccountControl:1.2.840.113556.1.4.803:=%d)(!(primaryGroupID=516)))", uacTrustedForDelegation)
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "userAccountControl", "objectClass", "servicePrincipalName", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return nil, err
	}

	var entries []kdOutputEntry
	for _, entry := range result.Entries {
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		e := kdOutputEntry{
			Account:        entry.GetAttributeValue("sAMAccountName"),
			DNS:            entry.GetAttributeValue("dNSHostName"),
			DelegationType: "Unconstrained",
			Disabled:       uac&uacAccountDisable != 0,
			S4U2Self:       uac&uacTrustedToAuthForDelegation != 0,
			Description:    entry.GetAttributeValue("description"),
			Risk:           "Can capture TGTs from any authenticating user",
		}
		if spns := entry.GetAttributeValues("servicePrincipalName"); len(spns) > 0 {
			e.SPNs = spns
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// kdFindConstrained finds accounts with msDS-AllowedToDelegateTo set
func kdFindConstrained(conn *ldap.Conn, baseDN string) structs.CommandResult {
	entries, err := kdConstrainedEntries(conn, baseDN)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error searching for constrained delegation: %v", err), Status: "error", Completed: true}
	}
	return kdMarshalResult(entries)
}

func kdConstrainedEntries(conn *ldap.Conn, baseDN string) ([]kdOutputEntry, error) {
	filter := "(msDS-AllowedToDelegateTo=*)"
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "msDS-AllowedToDelegateTo", "userAccountControl", "servicePrincipalName", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return nil, err
	}

	var entries []kdOutputEntry
	for _, entry := range result.Entries {
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		delegTo := entry.GetAttributeValues("msDS-AllowedToDelegateTo")
		s4u2self := uac&uacTrustedToAuthForDelegation != 0

		mode := "S4U2Proxy only"
		risk := ""
		if s4u2self {
			mode = "S4U2Self + S4U2Proxy"
			risk = "Protocol transition — can impersonate ANY user without interaction"
		}

		e := kdOutputEntry{
			Account:        entry.GetAttributeValue("sAMAccountName"),
			DNS:            entry.GetAttributeValue("dNSHostName"),
			DelegationType: "Constrained",
			Mode:           mode,
			Targets:        delegTo,
			Disabled:       uac&uacAccountDisable != 0,
			S4U2Self:       s4u2self,
			Description:    entry.GetAttributeValue("description"),
			Risk:           risk,
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// kdFindRBCD finds objects with msDS-AllowedToActOnBehalfOfOtherIdentity set
func kdFindRBCD(conn *ldap.Conn, baseDN string) structs.CommandResult {
	entries, err := kdRBCDEntries(conn, baseDN)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error searching for RBCD: %v", err), Status: "error", Completed: true}
	}
	return kdMarshalResult(entries)
}

func kdRBCDEntries(conn *ldap.Conn, baseDN string) ([]kdOutputEntry, error) {
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter,
		[]string{"sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "userAccountControl", "description"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return nil, err
	}

	var entries []kdOutputEntry
	for _, entry := range result.Entries {
		e := kdOutputEntry{
			Account:        entry.GetAttributeValue("sAMAccountName"),
			DNS:            entry.GetAttributeValue("dNSHostName"),
			DelegationType: "RBCD",
			Description:    entry.GetAttributeValue("description"),
		}
		sdBytes := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		if len(sdBytes) > 0 {
			aces := adcsParseSD(sdBytes)
			for _, ace := range aces {
				e.Targets = append(e.Targets, fmt.Sprintf("%s (mask: 0x%X)", ace.sid, ace.mask))
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// kdFindAll runs all delegation checks and produces a combined report
func kdFindAll(conn *ldap.Conn, baseDN string) structs.CommandResult {
	var allEntries []kdOutputEntry

	if entries, err := kdUnconstrainedEntries(conn, baseDN); err == nil {
		allEntries = append(allEntries, entries...)
	}
	if entries, err := kdConstrainedEntries(conn, baseDN); err == nil {
		allEntries = append(allEntries, entries...)
	}
	if entries, err := kdRBCDEntries(conn, baseDN); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Add protected accounts
	filter := fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", uacNotDelegated)
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, filter, []string{"sAMAccountName"}, nil)
	if result, err := conn.SearchWithPaging(req, 100); err == nil {
		for _, entry := range result.Entries {
			allEntries = append(allEntries, kdOutputEntry{
				Account:        entry.GetAttributeValue("sAMAccountName"),
				DelegationType: "Protected",
				Risk:           "NOT_DELEGATED flag set — cannot be impersonated via delegation",
			})
		}
	}

	return kdMarshalResult(allEntries)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
