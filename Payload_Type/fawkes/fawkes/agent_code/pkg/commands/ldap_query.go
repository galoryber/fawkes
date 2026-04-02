package commands

import (
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
	"admins": {
		filter:     "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "memberOf", "pwdLastSet", "lastLogonTimestamp", "userAccountControl"},
		desc:       "All administrative accounts (adminCount=1)",
	},
	"disabled": {
		filter:     "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "description", "pwdLastSet", "whenChanged"},
		desc:       "Disabled user accounts",
	},
	"gpo": {
		filter:     "(objectClass=groupPolicyContainer)",
		attributes: []string{"displayName", "cn", "gPCFileSysPath", "gPCMachineExtensionNames", "whenCreated", "whenChanged"},
		desc:       "Group Policy Objects",
	},
	"ou": {
		filter:     "(objectClass=organizationalUnit)",
		attributes: []string{"ou", "description", "gpLink", "whenCreated"},
		desc:       "Organizational Units",
	},
	"password-never-expires": {
		filter:     "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "pwdLastSet", "lastLogonTimestamp", "description"},
		desc:       "Accounts with password never expires flag",
	},
	"trusts": {
		filter:     "(objectClass=trustedDomain)",
		attributes: []string{"cn", "trustPartner", "trustDirection", "trustType", "trustAttributes", "flatName", "whenCreated", "whenChanged"},
		desc:       "Domain trust relationships",
	},
	"unconstrained": {
		filter:     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))",
		attributes: []string{"sAMAccountName", "dNSHostName", "operatingSystem", "userAccountControl", "lastLogonTimestamp", "description"},
		desc:       "Computers with unconstrained delegation (excluding DCs)",
	},
	"constrained": {
		filter:     "(msDS-AllowedToDelegateTo=*)",
		attributes: []string{"sAMAccountName", "userPrincipalName", "msDS-AllowedToDelegateTo", "userAccountControl", "objectClass", "description"},
		desc:       "Accounts with constrained delegation",
	},
}

func (c *LdapQueryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action <users|computers|groups|domain-admins|spns|asrep|admins|disabled|gpo|ou|password-never-expires|trusts|unconstrained|constrained|dacl|query> -server <DC>")
	}

	var args ldapQueryArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer structs.ZeroString(&args.Password)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller IP or hostname)")
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

	// Validate dacl action requires filter (target object name)
	if strings.ToLower(args.Action) == "dacl" && args.Filter == "" {
		return errorResult("Error: -filter parameter required for dacl action — specify the target object (sAMAccountName, CN, or full DN)")
	}

	// Connect to LDAP
	conn, err := ldapConnect(args)
	if err != nil {
		return errorf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	// Bind (authenticate)
	if err := ldapBind(conn, args); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	// Determine base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return errorf("Error detecting base DN: %v. Specify -base_dn manually.", err)
		}
	}

	// Handle dacl action separately (requires binary attribute parsing)
	if strings.ToLower(args.Action) == "dacl" {
		return ldapQueryDACL(conn, args, baseDN)
	}

	// Resolve filter and attributes
	filter, attributes, desc := resolveQuery(args, baseDN)
	if filter == "" {
		return errorResult("Error: action must be one of: users, computers, groups, domain-admins, spns, asrep, admins, disabled, gpo, ou, password-never-expires, trusts, unconstrained, constrained, dacl, query. For 'query', provide -filter. For 'dacl', provide -filter with target object name.")
	}

	// Execute search — use SizeLimit=0 with paging to avoid "Size Limit Exceeded"
	// errors from AD, then truncate client-side
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,  // let paging handle size
		30, // time limit in seconds
		false,
		filter,
		attributes,
		nil,
	)

	pagingSize := uint32(args.Limit)
	if pagingSize > 500 {
		pagingSize = 500
	}
	result, err := conn.SearchWithPaging(searchRequest, pagingSize)
	if err != nil {
		return errorf("Error executing LDAP search: %v", err)
	}

	// Truncate to requested limit
	totalFound := len(result.Entries)
	if totalFound > args.Limit {
		result.Entries = result.Entries[:args.Limit]
	}

	// Format output
	output := formatLDAPResults(result, args.Action, desc, baseDN, filter, totalFound)

	return successResult(output)
}

func ldapConnect(args ldapQueryArgs) (*ldap.Conn, error) {
	return ldapDial(args.Server, args.Port, args.UseTLS)
}

func ldapBind(conn *ldap.Conn, args ldapQueryArgs) error {
	return ldapBindSimple(conn, args.Username, args.Password)
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

// ldapQueryOutput is the JSON output for regular LDAP queries
type ldapQueryOutput struct {
	Query   string                       `json:"query"`
	BaseDN  string                       `json:"base_dn"`
	Filter  string                       `json:"filter"`
	Count   int                          `json:"count"`
	Entries []map[string]json.RawMessage `json:"entries"`
}

func formatLDAPResults(result *ldap.SearchResult, action, desc, baseDN, filter string, count int) string {
	output := ldapQueryOutput{
		Query:  desc,
		BaseDN: baseDN,
		Filter: filter,
		Count:  count,
	}

	for _, entry := range result.Entries {
		row := make(map[string]json.RawMessage)
		dnBytes, _ := json.Marshal(entry.DN)
		row["dn"] = dnBytes
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				valBytes, _ := json.Marshal(attr.Values[0])
				row[attr.Name] = valBytes
			} else if len(attr.Values) > 1 {
				valBytes, _ := json.Marshal(strings.Join(attr.Values, "; "))
				row[attr.Name] = valBytes
			}
		}
		output.Entries = append(output.Entries, row)
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Sprintf("Error marshaling JSON: %v", err)
	}
	return string(data)
}

