package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
		return errorResult("Error: parameters required. Use -action <list|members|user|privileged> -server <DC>")
	}

	var args netGroupArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer structs.ZeroString(&args.Password)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller IP or hostname)")
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
		return errorf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	if err := ngBind(conn, args); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	baseDN, err := ngDetectBaseDN(conn)
	if err != nil {
		return errorf("Error detecting base DN: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return ngList(conn, baseDN)
	case "members":
		if args.Group == "" {
			return errorResult("Error: group parameter required for members action")
		}
		return ngMembers(conn, baseDN, args.Group)
	case "user":
		if args.User == "" {
			return errorResult("Error: user parameter required for user action")
		}
		return ngUserGroups(conn, baseDN, args.User)
	case "privileged":
		return ngPrivileged(conn, baseDN)
	default:
		return errorResult("Error: action must be one of: list, members, user, privileged")
	}
}

func ngConnect(args netGroupArgs) (*ldap.Conn, error) {
	return ldapDial(args.Server, args.Port, args.UseTLS)
}

func ngBind(conn *ldap.Conn, args netGroupArgs) error {
	return ldapBindSimple(conn, args.Username, args.Password)
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
