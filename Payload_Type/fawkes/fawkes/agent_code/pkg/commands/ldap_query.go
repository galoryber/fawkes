package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LdapQueryCommand struct{}

func (c *LdapQueryCommand) Name() string        { return "ldap-query" }
func (c *LdapQueryCommand) Description() string { return "Query Active Directory via LDAP" }

type ldapQueryArgs struct {
	Action     string   `json:"action"`
	Filter     string   `json:"filter"`
	Server     string   `json:"server"`
	Port       int      `json:"port"`
	BaseDN     string   `json:"base_dn"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Attributes []string `json:"attributes"`
	Limit      int      `json:"limit"`
	UseTLS     bool     `json:"use_tls"`
}

// Preset queries for common red team actions
var presetQueries = map[string]struct {
	filter     string
	attributes []string
	desc       string
}{
	"users": {
		filter:     "(&(objectCategory=person)(objectClass=user))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf", "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "description"},
		desc:       "All domain users",
	},
	"computers": {
		filter:     "(objectClass=computer)",
		attributes: []string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp", "description"},
		desc:       "All domain computers",
	},
	"groups": {
		filter:     "(objectClass=group)",
		attributes: []string{"cn", "description", "member", "memberOf", "groupType"},
		desc:       "All domain groups",
	},
	"domain-admins": {
		filter:     "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,%s))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "lastLogonTimestamp", "pwdLastSet"},
		desc:       "Domain admin accounts (recursive group membership)",
	},
	"spns": {
		filter:     "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
		attributes: []string{"sAMAccountName", "servicePrincipalName", "pwdLastSet", "lastLogonTimestamp", "userAccountControl"},
		desc:       "Kerberoastable accounts (users with SPNs)",
	},
	"asrep": {
		filter:     "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "userAccountControl", "pwdLastSet"},
		desc:       "AS-REP roastable accounts (pre-auth disabled)",
	},
}

func (c *LdapQueryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <users|computers|groups|domain-admins|spns|asrep|query> -server <DC>",
			Status:    "error",
			Completed: true,
		}
	}

	var args ldapQueryArgs
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

	if args.Limit <= 0 {
		args.Limit = 100
	}
	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	// Connect to LDAP
	conn, err := ldapConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	// Bind (authenticate)
	if err := ldapBind(conn, args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error detecting base DN: %v. Specify -base_dn manually.", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Resolve filter and attributes
	filter, attributes, desc := resolveQuery(args, baseDN)
	if filter == "" {
		return structs.CommandResult{
			Output:    "Error: action must be one of: users, computers, groups, domain-admins, spns, asrep, query. For 'query', provide -filter.",
			Status:    "error",
			Completed: true,
		}
	}

	// Execute search
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		args.Limit,
		30, // time limit in seconds
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 500)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing LDAP search: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Format output
	output := formatLDAPResults(result, args.Action, desc, baseDN, filter, len(result.Entries))

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func ldapConnect(args ldapQueryArgs) (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", args.Server, args.Port)
	if args.UseTLS {
		return ldap.DialTLS("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return ldap.Dial("tcp", addr)
}

func ldapBind(conn *ldap.Conn, args ldapQueryArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	// Anonymous bind
	return conn.UnauthenticatedBind("")
}

func detectBaseDN(conn *ldap.Conn) (string, error) {
	// Query RootDSE to get defaultNamingContext
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entries returned")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = result.Entries[0].GetAttributeValue("rootDomainNamingContext")
	}
	if baseDN == "" {
		return "", fmt.Errorf("could not detect base DN from RootDSE")
	}

	return baseDN, nil
}

func resolveQuery(args ldapQueryArgs, baseDN string) (string, []string, string) {
	action := strings.ToLower(args.Action)

	if action == "query" {
		if args.Filter == "" {
			return "", nil, ""
		}
		attrs := args.Attributes
		if len(attrs) == 0 {
			attrs = []string{"*"}
		}
		return args.Filter, attrs, "Custom query"
	}

	preset, ok := presetQueries[action]
	if !ok {
		return "", nil, ""
	}

	filter := preset.filter
	// domain-admins needs baseDN substitution for the group DN
	if action == "domain-admins" {
		filter = fmt.Sprintf(filter, baseDN)
	}

	attributes := preset.attributes
	if len(args.Attributes) > 0 {
		attributes = args.Attributes
	}

	return filter, attributes, preset.desc
}

func formatLDAPResults(result *ldap.SearchResult, action, desc, baseDN, filter string, count int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("LDAP Query: %s\n", desc))
	sb.WriteString(fmt.Sprintf("Base DN: %s\n", baseDN))
	sb.WriteString(fmt.Sprintf("Filter: %s\n", filter))
	sb.WriteString(fmt.Sprintf("Results: %d\n", count))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for i, entry := range result.Entries {
		sb.WriteString(fmt.Sprintf("\n[%d] %s\n", i+1, entry.DN))
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				sb.WriteString(fmt.Sprintf("    %-30s %s\n", attr.Name+":", attr.Values[0]))
			} else if len(attr.Values) > 1 {
				sb.WriteString(fmt.Sprintf("    %s:\n", attr.Name))
				for _, v := range attr.Values {
					sb.WriteString(fmt.Sprintf("      - %s\n", v))
				}
			}
		}
	}

	return sb.String()
}
