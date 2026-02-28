package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type NetGroupCommand struct{}

func (c *NetGroupCommand) Name() string { return "net-group" }
func (c *NetGroupCommand) Description() string {
	return "Enumerate AD group memberships via LDAP (T1069.002)"
}

type netGroupArgs struct {
	Action   string `json:"action"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`
	Group    string `json:"group"`
	User     string `json:"user"`
}

// Well-known privileged group RIDs and names
var privilegedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Server Operators",
	"Print Operators",
	"DnsAdmins",
	"Group Policy Creator Owners",
	"Cert Publishers",
}

func (c *NetGroupCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <list|members|user|privileged> -server <DC>",
			Status:    "error",
			Completed: true,
		}
	}

	var args netGroupArgs
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

	conn, err := ngConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	if err := ngBind(conn, args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	baseDN, err := ngDetectBaseDN(conn)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error detecting base DN: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return ngList(conn, baseDN)
	case "members":
		if args.Group == "" {
			return structs.CommandResult{
				Output:    "Error: group parameter required for members action",
				Status:    "error",
				Completed: true,
			}
		}
		return ngMembers(conn, baseDN, args.Group)
	case "user":
		if args.User == "" {
			return structs.CommandResult{
				Output:    "Error: user parameter required for user action",
				Status:    "error",
				Completed: true,
			}
		}
		return ngUserGroups(conn, baseDN, args.User)
	case "privileged":
		return ngPrivileged(conn, baseDN)
	default:
		return structs.CommandResult{
			Output:    "Error: action must be one of: list, members, user, privileged",
			Status:    "error",
			Completed: true,
		}
	}
}

func ngConnect(args netGroupArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func ngBind(conn *ldap.Conn, args netGroupArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	return conn.UnauthenticatedBind("")
}

func ngDetectBaseDN(conn *ldap.Conn) (string, error) {
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

// ngList lists all groups with member counts
func ngList(conn *ldap.Conn, baseDN string) structs.CommandResult {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=group)",
		[]string{"cn", "description", "groupType", "member"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error searching groups: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	domain := trustDNToDomain(baseDN)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Domain Groups — %s (%d found)\n", domain, len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Sort by name
	sort.Slice(result.Entries, func(i, j int) bool {
		return strings.ToLower(result.Entries[i].GetAttributeValue("cn")) <
			strings.ToLower(result.Entries[j].GetAttributeValue("cn"))
	})

	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("cn")
		desc := entry.GetAttributeValue("description")
		members := entry.GetAttributeValues("member")
		gType := entry.GetAttributeValue("groupType")

		typeStr := ngGroupTypeStr(gType)
		sb.WriteString(fmt.Sprintf("%-40s  %s  Members: %d", name, typeStr, len(members)))
		if desc != "" {
			sb.WriteString(fmt.Sprintf("  — %s", desc))
		}
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// ngMembers lists members of a specific group (recursive)
func ngMembers(conn *ldap.Conn, baseDN, groupName string) structs.CommandResult {
	// First find the group DN
	groupDN, err := ngFindGroupDN(conn, baseDN, groupName)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding group %q: %v", groupName, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Recursive member query using LDAP_MATCHING_RULE_IN_CHAIN
	filter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(groupDN))

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"sAMAccountName", "objectClass", "userAccountControl", "description", "memberOf"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying members: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Members of %q (recursive) — %d found\n", groupName, len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	var users, computers, groups []string
	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		classes := entry.GetAttributeValues("objectClass")
		uac := entry.GetAttributeValue("userAccountControl")

		disabled := false
		if uacVal, err := strconv.ParseInt(uac, 10, 64); err == nil {
			disabled = uacVal&0x2 != 0
		}

		suffix := ""
		if disabled {
			suffix = " [DISABLED]"
		}

		if ngContainsClass(classes, "computer") {
			computers = append(computers, name+suffix)
		} else if ngContainsClass(classes, "group") {
			groups = append(groups, name+suffix)
		} else {
			users = append(users, name+suffix)
		}
	}

	sort.Strings(users)
	sort.Strings(computers)
	sort.Strings(groups)

	if len(users) > 0 {
		sb.WriteString(fmt.Sprintf("Users (%d):\n", len(users)))
		for _, u := range users {
			sb.WriteString(fmt.Sprintf("  - %s\n", u))
		}
		sb.WriteString("\n")
	}

	if len(computers) > 0 {
		sb.WriteString(fmt.Sprintf("Computers (%d):\n", len(computers)))
		for _, c := range computers {
			sb.WriteString(fmt.Sprintf("  - %s\n", c))
		}
		sb.WriteString("\n")
	}

	if len(groups) > 0 {
		sb.WriteString(fmt.Sprintf("Nested Groups (%d):\n", len(groups)))
		for _, g := range groups {
			sb.WriteString(fmt.Sprintf("  - %s\n", g))
		}
		sb.WriteString("\n")
	}

	if len(result.Entries) == 0 {
		sb.WriteString("No members found.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// ngUserGroups finds all groups a user belongs to (recursive)
func ngUserGroups(conn *ldap.Conn, baseDN, userName string) structs.CommandResult {
	// Find the user first
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(userName))
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 10, false, filter,
		[]string{"sAMAccountName", "distinguishedName", "memberOf"},
		nil)

	result, err := conn.Search(req)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding user %q: %v", userName, err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(result.Entries) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("User %q not found", userName),
			Status:    "error",
			Completed: true,
		}
	}

	userDN := result.Entries[0].GetAttributeValue("distinguishedName")

	// Now find all groups this user is a member of (recursive)
	groupFilter := fmt.Sprintf("(member:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(userDN))
	groupReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, groupFilter,
		[]string{"cn", "groupType", "description"},
		nil)

	groupResult, err := conn.SearchWithPaging(groupReq, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying groups for %q: %v", userName, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Group Memberships for %q — %d groups\n", userName, len(groupResult.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Separate privileged and normal groups
	var privGroups, normalGroups []string
	privSet := make(map[string]bool)
	for _, pg := range privilegedGroups {
		privSet[strings.ToLower(pg)] = true
	}

	for _, entry := range groupResult.Entries {
		name := entry.GetAttributeValue("cn")
		gType := ngGroupTypeStr(entry.GetAttributeValue("groupType"))
		desc := entry.GetAttributeValue("description")

		line := fmt.Sprintf("%s  %s", name, gType)
		if desc != "" {
			line += fmt.Sprintf("  — %s", desc)
		}

		if privSet[strings.ToLower(name)] {
			privGroups = append(privGroups, line)
		} else {
			normalGroups = append(normalGroups, line)
		}
	}

	sort.Strings(privGroups)
	sort.Strings(normalGroups)

	if len(privGroups) > 0 {
		sb.WriteString(fmt.Sprintf("[!] PRIVILEGED Groups (%d):\n", len(privGroups)))
		for _, g := range privGroups {
			sb.WriteString(fmt.Sprintf("  * %s\n", g))
		}
		sb.WriteString("\n")
	}

	if len(normalGroups) > 0 {
		sb.WriteString(fmt.Sprintf("Other Groups (%d):\n", len(normalGroups)))
		for _, g := range normalGroups {
			sb.WriteString(fmt.Sprintf("  - %s\n", g))
		}
	}

	if len(groupResult.Entries) == 0 {
		sb.WriteString("User has no group memberships (besides primary group).\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// ngPrivileged finds all privileged groups and their members
func ngPrivileged(conn *ldap.Conn, baseDN string) structs.CommandResult {
	domain := trustDNToDomain(baseDN)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Privileged Group Enumeration — %s\n", domain))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	totalMembers := 0
	for _, groupName := range privilegedGroups {
		// Find the group
		filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
		req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			1, 10, false, filter,
			[]string{"cn", "distinguishedName"},
			nil)

		result, err := conn.Search(req)
		if err != nil || len(result.Entries) == 0 {
			continue // Group doesn't exist in this domain
		}

		groupDN := result.Entries[0].DN

		// Get recursive members
		memberFilter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(groupDN))
		memberReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, memberFilter,
			[]string{"sAMAccountName", "objectClass", "userAccountControl"},
			nil)

		memberResult, err := conn.SearchWithPaging(memberReq, 100)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s — error querying members\n", groupName))
			continue
		}

		if len(memberResult.Entries) == 0 {
			continue // Empty group, skip
		}

		sb.WriteString(fmt.Sprintf("%s (%d members)\n", groupName, len(memberResult.Entries)))
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		for _, entry := range memberResult.Entries {
			name := entry.GetAttributeValue("sAMAccountName")
			classes := entry.GetAttributeValues("objectClass")
			uac := entry.GetAttributeValue("userAccountControl")

			typeStr := "user"
			if ngContainsClass(classes, "computer") {
				typeStr = "computer"
			} else if ngContainsClass(classes, "group") {
				typeStr = "group"
			}

			disabled := ""
			if uacVal, err := strconv.ParseInt(uac, 10, 64); err == nil && uacVal&0x2 != 0 {
				disabled = " [DISABLED]"
			}

			sb.WriteString(fmt.Sprintf("  - %s (%s)%s\n", name, typeStr, disabled))
		}
		sb.WriteString("\n")
		totalMembers += len(memberResult.Entries)
	}

	if totalMembers == 0 {
		sb.WriteString("No privileged group members found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Total privileged accounts: %d\n", totalMembers))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// ngFindGroupDN finds the DN of a group by name
func ngFindGroupDN(conn *ldap.Conn, baseDN, groupName string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 10, false, filter,
		[]string{"distinguishedName"},
		nil)

	result, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("group %q not found", groupName)
	}
	return result.Entries[0].DN, nil
}

// ngGroupTypeStr converts groupType integer to readable string
func ngGroupTypeStr(gType string) string {
	val, err := strconv.ParseInt(gType, 10, 64)
	if err != nil {
		return "[?]"
	}

	scope := "Domain Local"
	if val&0x2 != 0 {
		scope = "Global"
	} else if val&0x8 != 0 {
		scope = "Universal"
	}

	kind := "Distribution"
	if val&int64(0x80000000) != 0 {
		kind = "Security"
	}

	return fmt.Sprintf("[%s %s]", scope, kind)
}

// ngContainsClass checks if an objectClass slice contains a specific class
func ngContainsClass(classes []string, target string) bool {
	for _, c := range classes {
		if strings.EqualFold(c, target) {
			return true
		}
	}
	return false
}
