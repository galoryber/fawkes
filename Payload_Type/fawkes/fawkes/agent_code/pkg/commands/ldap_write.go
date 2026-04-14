package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LdapWriteCommand struct{}

func (c *LdapWriteCommand) Name() string { return "ldap-write" }
func (c *LdapWriteCommand) Description() string {
	return "Modify Active Directory objects via LDAP"
}

type ldapWriteArgs struct {
	Action   string   `json:"action"`
	Server   string   `json:"server"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	BaseDN   string   `json:"base_dn"`
	UseTLS   bool     `json:"use_tls"`
	Target   string   `json:"target"`
	Group    string   `json:"group"`
	Attr     string   `json:"attr"`
	Value    string   `json:"value"`
	Values   []string `json:"values"`
}

func (c *LdapWriteCommand) Execute(task structs.Task) structs.CommandResult {
	allActions := "add-member, remove-member, set-attr, add-attr, remove-attr, set-spn, disable, enable, set-password, add-computer, delete-object, set-rbcd, clear-rbcd, shadow-cred, clear-shadow-cred, gpo-task, gpo-script, template-esc1, template-esc4"
	if task.Params == "" {
		return errorf("Error: parameters required. Use -action <%s> -server <DC>", allActions)
	}

	args, parseErr := unmarshalParams[ldapWriteArgs](task)
	if parseErr != nil {
		return *parseErr
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

	// Validate action before connecting
	action := strings.ToLower(args.Action)
	validActions := map[string]bool{
		"add-member": true, "remove-member": true,
		"set-attr": true, "add-attr": true, "remove-attr": true,
		"set-spn": true, "disable": true, "enable": true, "set-password": true,
		"add-computer": true, "delete-object": true,
		"set-rbcd": true, "clear-rbcd": true,
		"shadow-cred": true, "clear-shadow-cred": true,
		"gpo-task": true, "gpo-script": true,
		"template-esc1": true, "template-esc4": true,
	}
	if !validActions[action] {
		return errorf("Unknown action: %s\nAvailable: %s", args.Action, allActions)
	}

	// set-password requires LDAPS
	if action == "set-password" && !args.UseTLS {
		return errorResult("Error: set-password requires LDAPS (-use_tls true). AD rejects password changes over unencrypted LDAP.")
	}

	// Connect
	conn, err := ldapConnect(ldapQueryArgs{
		Server: args.Server, Port: args.Port, UseTLS: args.UseTLS,
		Username: args.Username, Password: args.Password,
	})
	if err != nil {
		return errorf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	// Bind
	if err := ldapBind(conn, ldapQueryArgs{Username: args.Username, Password: args.Password}); err != nil {
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

	switch strings.ToLower(args.Action) {
	case "add-member":
		return ldapAddMember(conn, args, baseDN)
	case "remove-member":
		return ldapRemoveMember(conn, args, baseDN)
	case "set-attr":
		return ldapSetAttr(conn, args, baseDN)
	case "add-attr":
		return ldapAddAttr(conn, args, baseDN)
	case "remove-attr":
		return ldapRemoveAttr(conn, args, baseDN)
	case "set-spn":
		return ldapSetSPN(conn, args, baseDN)
	case "disable":
		return ldapToggleAccount(conn, args, baseDN, true)
	case "enable":
		return ldapToggleAccount(conn, args, baseDN, false)
	case "set-password":
		return ldapSetPassword(conn, args, baseDN)
	case "add-computer":
		return ldapAddComputer(conn, args, baseDN)
	case "delete-object":
		return ldapDeleteObject(conn, args, baseDN)
	case "set-rbcd":
		return ldapSetRBCD(conn, args, baseDN)
	case "clear-rbcd":
		return ldapClearRBCD(conn, args, baseDN)
	case "shadow-cred":
		return ldapShadowCred(conn, args, baseDN)
	case "clear-shadow-cred":
		return ldapClearShadowCred(conn, args, baseDN)
	case "gpo-task":
		return ldapGPOAddTask(conn, args, baseDN)
	case "gpo-script":
		return ldapGPOAddScript(conn, args, baseDN)
	case "template-esc1":
		return ldapTemplateESC1(conn, args, baseDN)
	case "template-esc4":
		return ldapTemplateESC4(conn, args, baseDN)
	default:
		// Unreachable — action is validated before connection
		return errorResult("Unknown action")
	}
}

// ldapResolveDN resolves a sAMAccountName to its full distinguished name.
func ldapResolveDN(conn *ldap.Conn, name string, baseDN string) (string, error) {
	// If it's already a DN, return as-is
	if strings.Contains(name, "=") {
		return name, nil
	}

	// Search for the object by sAMAccountName
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 10, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(name)),
		[]string{"distinguishedName"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("search failed: %v", err)
	}

	if len(result.Entries) == 0 {
		// Try CN search as fallback
		searchRequest = ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1, 10, false,
			fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(name)),
			[]string{"distinguishedName"},
			nil,
		)
		result, err = conn.Search(searchRequest)
		if err != nil || len(result.Entries) == 0 {
			return "", fmt.Errorf("object '%s' not found", name)
		}
	}

	return result.Entries[0].DN, nil
}
