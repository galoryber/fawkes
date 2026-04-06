package commands

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// daclSIDToBytes converts a string SID (S-1-5-21-...) to binary format
func daclSIDToBytes(sid string) []byte {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return nil
	}

	revision, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}

	authority, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil
	}

	subAuthCount := len(parts) - 3
	result := make([]byte, 8+subAuthCount*4)
	result[0] = byte(revision)
	result[1] = byte(subAuthCount)
	// Authority (6 bytes, big-endian)
	for i := 0; i < 6; i++ {
		result[2+i] = byte(authority >> (8 * uint(5-i)))
	}
	// Sub-authorities (little-endian uint32)
	for i := 0; i < subAuthCount; i++ {
		subAuth, err := strconv.ParseUint(parts[3+i], 10, 32)
		if err != nil {
			return nil
		}
		binary.LittleEndian.PutUint32(result[8+i*4:], uint32(subAuth))
	}

	return result
}

// daclWellKnownRID maps well-known domain RIDs to names
func daclWellKnownRID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 5 {
		return ""
	}

	// Check for domain-relative well-known RIDs
	lastPart := parts[len(parts)-1]
	ridVal, _ := strconv.ParseUint(lastPart, 10, 32)
	rid := uint32(ridVal)

	switch rid {
	case 500:
		return "Administrator"
	case 502:
		return "krbtgt"
	case 512:
		return "Domain Admins"
	case 513:
		return "Domain Users"
	case 514:
		return "Domain Guests"
	case 515:
		return "Domain Computers"
	case 516:
		return "Domain Controllers"
	case 517:
		return "Cert Publishers"
	case 518:
		return "Schema Admins"
	case 519:
		return "Enterprise Admins"
	case 520:
		return "Group Policy Creator Owners"
	case 526:
		return "Key Admins"
	case 527:
		return "Enterprise Key Admins"
	case 553:
		return "RAS and IAS Servers"
	case 571:
		return "Allowed RODC Password Replication Group"
	case 572:
		return "Denied RODC Password Replication Group"
	}

	return ""
}

// daclDescribePermissions returns a human-readable permission description
func daclDescribePermissions(mask uint32, aceType byte, objectGUID []byte) string {
	var perms []string

	// Generic rights
	if mask&0x10000000 != 0 {
		return "GenericAll (FULL CONTROL)"
	}
	if mask&0x80000000 != 0 {
		perms = append(perms, "GenericRead")
	}
	if mask&0x40000000 != 0 {
		perms = append(perms, "GenericWrite")
	}
	if mask&0x20000000 != 0 {
		perms = append(perms, "GenericExecute")
	}

	// Standard rights
	if mask&0x000F0000 == 0x000F0000 {
		perms = append(perms, "StandardAll")
	} else {
		if mask&0x00080000 != 0 {
			perms = append(perms, "WriteOwner")
		}
		if mask&0x00040000 != 0 {
			perms = append(perms, "WriteDACL")
		}
		if mask&0x00020000 != 0 {
			perms = append(perms, "ReadControl")
		}
		if mask&0x00010000 != 0 {
			perms = append(perms, "Delete")
		}
	}

	// DS-specific rights
	if mask&0x00000100 != 0 {
		if aceType == 0x05 && len(objectGUID) == 16 {
			guidName := daclGUIDName(objectGUID)
			perms = append(perms, fmt.Sprintf("ExtendedRight(%s)", guidName))
		} else {
			perms = append(perms, "AllExtendedRights")
		}
	}
	if mask&0x00000020 != 0 {
		if aceType == 0x05 && len(objectGUID) == 16 {
			guidName := daclGUIDName(objectGUID)
			perms = append(perms, fmt.Sprintf("WriteProperty(%s)", guidName))
		} else {
			perms = append(perms, "WriteAllProperties")
		}
	}
	if mask&0x00000010 != 0 {
		perms = append(perms, "ReadProperty")
	}
	if mask&0x00000008 != 0 {
		perms = append(perms, "ListObject")
	}
	if mask&0x00000004 != 0 {
		perms = append(perms, "CreateChild")
	}
	if mask&0x00000002 != 0 {
		perms = append(perms, "DeleteChild")
	}
	if mask&0x00000001 != 0 {
		perms = append(perms, "ListChildren")
	}

	if len(perms) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}

	return strings.Join(perms, ", ")
}

// daclAssessRisk categorizes an ACE as dangerous, notable, or standard
func daclAssessRisk(mask uint32, aceType byte, sid string, objectGUID []byte) string {
	// Well-known high-privilege SIDs are expected to have permissions
	highPrivSIDs := map[string]bool{
		"S-1-5-18":     true, // SYSTEM
		"S-1-5-32-544": true, // BUILTIN\Administrators
		"S-1-5-9":      true, // Enterprise Domain Controllers
		"S-1-3-0":      true, // Creator Owner
	}

	// Domain Admins (RID 512), Enterprise Admins (519), Domain Controllers (516)
	parts := strings.Split(sid, "-")
	if len(parts) >= 5 {
		lastPart := parts[len(parts)-1]
		switch lastPart {
		case "512", "516", "518", "519":
			highPrivSIDs[sid] = true
		}
	}

	// Low-priv SIDs that shouldn't have dangerous permissions
	lowPrivSIDs := map[string]bool{
		"S-1-1-0":  true, // Everyone
		"S-1-5-7":  true, // Anonymous
		"S-1-5-11": true, // Authenticated Users
	}
	if len(parts) >= 5 {
		lastPart := parts[len(parts)-1]
		switch lastPart {
		case "513", "515": // Domain Users, Domain Computers
			lowPrivSIDs[sid] = true
		}
	}

	// User-Change-Password (ab721a53) is not dangerous — requires knowing current password
	isChangePassword := aceType == 0x05 && len(objectGUID) == 16 &&
		daclGUIDName(objectGUID) == "User-Change-Password"

	isDangerous := !isChangePassword && (mask&0x10000000 != 0 || // GenericAll
		mask&0x40000000 != 0 || // GenericWrite
		mask&0x00080000 != 0 || // WriteOwner
		mask&0x00040000 != 0 || // WriteDACL
		mask&0x00000020 != 0 || // WriteProperty
		mask&0x00000100 != 0) // ExtendedRights (includes ForceChangePassword)

	if !isDangerous {
		return "standard"
	}

	if highPrivSIDs[sid] {
		return "standard" // Expected for high-priv
	}

	if lowPrivSIDs[sid] {
		return "dangerous" // Low-priv with dangerous perms = attack target
	}

	// Unknown SID with dangerous perms
	return "notable"
}

// daclGUIDName maps well-known AD attribute/extended-right GUIDs to names
func daclGUIDName(guid []byte) string {
	if len(guid) != 16 {
		return "unknown"
	}

	// Convert to canonical GUID string (mixed-endian)
	d1 := binary.LittleEndian.Uint32(guid[0:4])
	d2 := binary.LittleEndian.Uint16(guid[4:6])
	d3 := binary.LittleEndian.Uint16(guid[6:8])
	guidStr := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15])

	knownGUIDs := map[string]string{
		// Extended Rights
		"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
		"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
		"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
		"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
		"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
		"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
		"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
		"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
		"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
		"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
		// Property Sets / Attributes
		"bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
		"bf967a7f-0de6-11d0-a285-00aa003049e2": "userCertificate",
		"f30e3bc2-9ff0-11d1-b603-0000f80367c1": "GPC-File-Sys-Path",
		"bf967a86-0de6-11d0-a285-00aa003049e2": "servicePrincipalName",
		"5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
		"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
		"5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
		"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
		"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
		"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
		"e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
		"e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
		"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
		"6db69a1c-9422-11d1-aebd-0000f80367c1": "Terminal-Server",
		"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Server",
		"ea1b7b93-5e48-46d5-bc6c-4df4fda78a35": "msDS-SupportedEncryptionTypes",
	}

	if name, ok := knownGUIDs[guidStr]; ok {
		return name
	}

	return guidStr
}
