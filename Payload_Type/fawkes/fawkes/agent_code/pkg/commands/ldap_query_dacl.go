package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

// ldapQueryDACL queries the DACL (access control list) of a specific AD object
// and displays who has what permissions. Uses the -filter parameter as the target
// object name (sAMAccountName, CN, or full DN).
func ldapQueryDACL(conn *ldap.Conn, args ldapQueryArgs, baseDN string) structs.CommandResult {
	target := args.Filter
	if target == "" {
		return errorResult("Error: -filter parameter required — specify the target object (sAMAccountName, CN, or full DN)")
	}

	// Resolve target to DN
	targetDN, err := ldapResolveDN(conn, target, baseDN)
	if err != nil {
		return errorf("Error resolving target '%s': %v", target, err)
	}

	// Query nTSecurityDescriptor (binary attribute)
	searchReq := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor", "objectClass"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return errorf("Error querying nTSecurityDescriptor: %v", err)
	}

	if len(result.Entries) == 0 {
		return errorf("Error: object not found: %s", targetDN)
	}

	sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sd) < 20 {
		return errorf("Error: nTSecurityDescriptor too short or not returned (length %d). May need elevated privileges.", len(sd))
	}

	objClass := result.Entries[0].GetAttributeValues("objectClass")

	// Parse the security descriptor
	aces := daclParseSD(sd)

	// Build SID resolution cache
	sidCache := daclResolveSIDs(conn, aces, baseDN)

	// Build JSON output
	type daclACEOutput struct {
		Principal   string `json:"principal"`
		SID         string `json:"sid"`
		Permissions string `json:"permissions"`
		Risk        string `json:"risk"`
	}
	type daclOutput struct {
		Mode        string          `json:"mode"`
		Target      string          `json:"target"`
		ObjectClass string          `json:"object_class"`
		ACECount    int             `json:"ace_count"`
		Owner       string          `json:"owner"`
		Dangerous   int             `json:"dangerous"`
		Notable     int             `json:"notable"`
		ACEs        []daclACEOutput `json:"aces"`
	}

	out := daclOutput{
		Mode:        "dacl",
		Target:      targetDN,
		ObjectClass: strings.Join(objClass, ", "),
		ACECount:    len(aces),
	}

	// Parse owner if present
	ownerOff := int(binary.LittleEndian.Uint32(sd[4:8]))
	if ownerOff > 0 && ownerOff+8 <= len(sd) {
		ownerSID := adcsParseSID(sd[ownerOff:])
		ownerName := sidCache[ownerSID]
		if ownerName == "" {
			ownerName = ownerSID
		}
		out.Owner = ownerName
	}

	for _, ace := range aces {
		principal := sidCache[ace.sid]
		if principal == "" {
			principal = ace.sid
		}
		perms := daclDescribePermissions(ace.mask, ace.aceType, ace.objectGUID)
		risk := daclAssessRisk(ace.mask, ace.aceType, ace.sid, ace.objectGUID)

		out.ACEs = append(out.ACEs, daclACEOutput{
			Principal:   principal,
			SID:         ace.sid,
			Permissions: perms,
			Risk:        risk,
		})

		switch risk {
		case "dangerous":
			out.Dangerous++
		case "notable":
			out.Notable++
		}
	}

	data, err := json.Marshal(out)
	if err != nil {
		return errorf("Error marshaling DACL JSON: %v", err)
	}

	return successResult(string(data))
}

type daclACE struct {
	sid        string
	mask       uint32
	aceType    byte
	objectGUID []byte
}

// daclParseSD parses a binary security descriptor to extract DACL ACEs
func daclParseSD(sd []byte) []daclACE {
	if len(sd) < 20 {
		return nil
	}

	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset >= len(sd) {
		return nil
	}

	return daclParseACL(sd, daclOffset)
}

// daclParseACL parses an ACL at the given offset
func daclParseACL(sd []byte, offset int) []daclACE {
	if offset+8 > len(sd) {
		return nil
	}

	aceCount := int(binary.LittleEndian.Uint16(sd[offset+4 : offset+6]))
	aces := make([]daclACE, 0, aceCount)
	pos := offset + 8

	for i := 0; i < aceCount && pos+4 <= len(sd); i++ {
		aceType := sd[pos]
		aceSize := int(binary.LittleEndian.Uint16(sd[pos+2 : pos+4]))

		if aceSize < 4 || pos+aceSize > len(sd) {
			break
		}

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE_TYPE
			if pos+8 <= len(sd) {
				mask := binary.LittleEndian.Uint32(sd[pos+4 : pos+8])
				sid := adcsParseSID(sd[pos+8 : pos+aceSize])
				if sid != "" {
					aces = append(aces, daclACE{sid: sid, mask: mask, aceType: aceType})
				}
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE_TYPE
			if pos+12 <= len(sd) {
				mask := binary.LittleEndian.Uint32(sd[pos+4 : pos+8])
				flags := binary.LittleEndian.Uint32(sd[pos+8 : pos+12])

				sidStart := pos + 12
				var objectGUID []byte

				if flags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
					if sidStart+16 <= len(sd) {
						objectGUID = make([]byte, 16)
						copy(objectGUID, sd[sidStart:sidStart+16])
						sidStart += 16
					}
				}
				if flags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
					sidStart += 16
				}

				if sidStart < pos+aceSize {
					sid := adcsParseSID(sd[sidStart : pos+aceSize])
					if sid != "" {
						aces = append(aces, daclACE{sid: sid, mask: mask, aceType: aceType, objectGUID: objectGUID})
					}
				}
			}
		}

		pos += aceSize
	}

	return aces
}

// daclResolveSIDs resolves SIDs to human-readable names via LDAP
func daclResolveSIDs(conn *ldap.Conn, aces []daclACE, baseDN string) map[string]string {
	cache := map[string]string{
		"S-1-0-0":      "Nobody",
		"S-1-1-0":      "Everyone",
		"S-1-3-0":      "Creator Owner",
		"S-1-3-4":      "Owner Rights",
		"S-1-5-7":      "Anonymous",
		"S-1-5-9":      "Enterprise Domain Controllers",
		"S-1-5-10":     "Self",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-18":     "SYSTEM",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-32-548": "BUILTIN\\Account Operators",
		"S-1-5-32-549": "BUILTIN\\Server Operators",
		"S-1-5-32-550": "BUILTIN\\Print Operators",
		"S-1-5-32-551": "BUILTIN\\Backup Operators",
		"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	}

	// Collect unique SIDs that need resolution
	toResolve := make(map[string]bool)
	for _, ace := range aces {
		if _, ok := cache[ace.sid]; !ok {
			toResolve[ace.sid] = true
		}
	}

	// Resolve domain SIDs via LDAP
	for sid := range toResolve {
		// Encode SID as binary for LDAP filter
		binSID := daclSIDToBytes(sid)
		if binSID == nil {
			continue
		}

		// Build escaped binary filter
		var escaped strings.Builder
		for _, b := range binSID {
			escaped.WriteString(fmt.Sprintf("\\%02x", b))
		}

		searchReq := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1, 5, false,
			fmt.Sprintf("(objectSid=%s)", escaped.String()),
			[]string{"sAMAccountName", "cn"},
			nil,
		)

		result, err := conn.Search(searchReq)
		if err == nil && len(result.Entries) > 0 {
			name := result.Entries[0].GetAttributeValue("sAMAccountName")
			if name == "" {
				name = result.Entries[0].GetAttributeValue("cn")
			}
			if name != "" {
				cache[sid] = name
			}
		}

		// Also try well-known domain RIDs
		if _, ok := cache[sid]; !ok {
			cache[sid] = daclWellKnownRID(sid)
		}
	}

	return cache
}

