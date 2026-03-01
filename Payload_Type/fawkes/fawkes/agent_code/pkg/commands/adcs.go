package commands

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type AdcsCommand struct{}

func (c *AdcsCommand) Name() string { return "adcs" }
func (c *AdcsCommand) Description() string {
	return "Enumerate AD Certificate Services and find vulnerable templates"
}

type adcsArgs struct {
	Action   string `json:"action"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`
}

// EKU OIDs relevant for ESC detection
const (
	oidClientAuth       = "1.3.6.1.5.5.7.3.2"
	oidPKINITClient     = "1.3.6.1.5.2.3.4"
	oidSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	oidAnyPurpose       = "2.5.29.37.0"
	oidCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"
	oidServerAuth       = "1.3.6.1.5.5.7.3.1"
)

// Certificate name flag
const ctFlagEnrolleeSuppliesSubject = 1

// Certificate enrollment extended right GUID (mixed-endian binary)
var enrollmentGUID = guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")

// Access mask constants
const (
	adsRightDSControlAccess = 0x00000100
	adsGenericAll           = 0x10000000
	adsWriteDACL            = 0x00040000
	adsWriteOwner           = 0x00080000
)

// Well-known low-privilege SIDs
var lowPrivSIDMap = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-545": "BUILTIN\\Users",
}

// Domain-relative RIDs for low-privilege groups
var lowPrivRIDMap = map[uint32]string{
	513: "Domain Users",
	515: "Domain Computers",
}

func (c *AdcsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <cas|templates|find> -server <DC>",
			Status:    "error",
			Completed: true,
		}
	}

	var args adcsArgs
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

	conn, err := adcsConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	if err := adcsBind(conn, args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	configDN, baseDN, err := adcsGetConfigDN(conn)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error detecting configuration DN: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "cas":
		return adcsEnumerateCAs(conn, configDN)
	case "templates":
		return adcsEnumerateTemplates(conn, configDN)
	case "find":
		return adcsFindVulnerable(conn, configDN, baseDN)
	default:
		return structs.CommandResult{
			Output:    "Error: action must be one of: cas, templates, find",
			Status:    "error",
			Completed: true,
		}
	}
}

func adcsConnect(args adcsArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func adcsBind(conn *ldap.Conn, args adcsArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	return conn.UnauthenticatedBind("")
}

func adcsGetConfigDN(conn *ldap.Conn) (string, string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false, "(objectClass=*)",
		[]string{"configurationNamingContext", "defaultNamingContext"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return "", "", fmt.Errorf("RootDSE query failed: %v", err)
	}
	if len(result.Entries) == 0 {
		return "", "", fmt.Errorf("no RootDSE entries returned")
	}

	configDN := result.Entries[0].GetAttributeValue("configurationNamingContext")
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if configDN == "" {
		return "", "", fmt.Errorf("could not detect configurationNamingContext")
	}
	return configDN, baseDN, nil
}

// adcsEnumerateCAs lists all Certificate Authorities and their published templates
func adcsEnumerateCAs(conn *ldap.Conn, configDN string) structs.CommandResult {
	searchBase := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)

	req := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectCategory=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "cACertificateDN", "certificateTemplates", "displayName"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying CAs: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Certificate Authorities (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	for i, entry := range result.Entries {
		sb.WriteString(fmt.Sprintf("\n[CA %d] %s\n", i+1, entry.GetAttributeValue("cn")))
		sb.WriteString(fmt.Sprintf("  DNS Name:    %s\n", entry.GetAttributeValue("dNSHostName")))
		sb.WriteString(fmt.Sprintf("  CA DN:       %s\n", entry.GetAttributeValue("cACertificateDN")))

		templates := entry.GetAttributeValues("certificateTemplates")
		sb.WriteString(fmt.Sprintf("  Templates:   %d published\n", len(templates)))
		for _, t := range templates {
			sb.WriteString(fmt.Sprintf("    - %s\n", t))
		}
	}

	if len(result.Entries) == 0 {
		sb.WriteString("\nNo Certificate Authorities found. ADCS may not be installed.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// adcsEnumerateTemplates lists all certificate templates with security-relevant attributes
func adcsEnumerateTemplates(conn *ldap.Conn, configDN string) structs.CommandResult {
	searchBase := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	req := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"msPKI-Template-Schema-Version",
		}, nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying templates: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Certificate Templates (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	for i, entry := range result.Entries {
		name := entry.GetAttributeValue("cn")
		display := entry.GetAttributeValue("displayName")
		nameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
		raSig := entry.GetAttributeValue("msPKI-RA-Signature")
		ekus := entry.GetAttributeValues("pKIExtendedKeyUsage")
		appPolicies := entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		schemaVer := entry.GetAttributeValue("msPKI-Template-Schema-Version")

		sb.WriteString(fmt.Sprintf("\n[%d] %s", i+1, name))
		if display != "" && display != name {
			sb.WriteString(fmt.Sprintf(" (%s)", display))
		}
		sb.WriteString("\n")

		nameFlags, _ := strconv.ParseInt(nameFlag, 10, 64)
		if nameFlags&ctFlagEnrolleeSuppliesSubject != 0 {
			sb.WriteString("  Subject:     ENROLLEE_SUPPLIES_SUBJECT\n")
		} else {
			sb.WriteString("  Subject:     CA-provided\n")
		}

		allEKUs := append(ekus, appPolicies...)
		if len(allEKUs) == 0 {
			sb.WriteString("  EKUs:        <none> (any purpose)\n")
		} else {
			ekuNames := make([]string, 0, len(allEKUs))
			for _, eku := range allEKUs {
				ekuNames = append(ekuNames, adcsResolveEKU(eku))
			}
			sb.WriteString(fmt.Sprintf("  EKUs:        %s\n", strings.Join(ekuNames, ", ")))
		}

		sb.WriteString(fmt.Sprintf("  RA Sigs:     %s\n", raSig))
		sb.WriteString(fmt.Sprintf("  Schema:      v%s\n", schemaVer))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// adcsFindVulnerable checks published templates for ESC1-ESC4 vulnerabilities
func adcsFindVulnerable(conn *ldap.Conn, configDN, baseDN string) structs.CommandResult {
	// Get published templates from CAs
	caBase := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	caReq := ldap.NewSearchRequest(caBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectCategory=pKIEnrollmentService)",
		[]string{"cn", "certificateTemplates"}, nil)

	caResult, err := conn.Search(caReq)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying CAs: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build published template → CA name mapping
	publishedTemplates := make(map[string][]string)
	for _, ca := range caResult.Entries {
		caName := ca.GetAttributeValue("cn")
		for _, t := range ca.GetAttributeValues("certificateTemplates") {
			publishedTemplates[t] = append(publishedTemplates[t], caName)
		}
	}

	// Query templates with security descriptor for permission analysis
	templateBase := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)
	templateReq := ldap.NewSearchRequest(templateBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"nTSecurityDescriptor",
		}, nil)

	templateResult, err := conn.SearchWithPaging(templateReq, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying templates: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("ADCS Vulnerability Assessment\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("CAs: %d | Templates: %d | Published: %d\n\n",
		len(caResult.Entries), len(templateResult.Entries), len(publishedTemplates)))

	vulnCount := 0

	for _, entry := range templateResult.Entries {
		name := entry.GetAttributeValue("cn")

		cas, published := publishedTemplates[name]
		if !published {
			continue
		}

		nameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
		raSig := entry.GetAttributeValue("msPKI-RA-Signature")
		ekus := entry.GetAttributeValues("pKIExtendedKeyUsage")
		appPolicies := entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")

		nameFlags, _ := strconv.ParseInt(nameFlag, 10, 64)
		raSigs, _ := strconv.ParseInt(raSig, 10, 64)
		allEKUs := append(ekus, appPolicies...)

		// Parse enrollment and write permissions from SD
		enrollers := adcsParseEnrollmentPerms(sdBytes)
		lowPrivEnrollers := adcsFilterLowPriv(enrollers)
		writers := adcsParseWritePerms(sdBytes)
		lowPrivWriters := adcsFilterLowPriv(writers)

		var findings []string

		// ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment + no manager approval
		if nameFlags&ctFlagEnrolleeSuppliesSubject != 0 && adcsHasAuthEKU(allEKUs) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC2: Any purpose or SubCA EKU + low-priv enrollment
		if (adcsHasAnyPurposeEKU(allEKUs) || len(allEKUs) == 0) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC2: Any purpose/SubCA EKU + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC3: Certificate Request Agent EKU + low-priv enrollment
		if adcsHasCertRequestAgentEKU(allEKUs) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC3: Certificate Request Agent + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC4: Low-priv user has write access to template
		if len(lowPrivWriters) > 0 {
			findings = append(findings, fmt.Sprintf("ESC4: Template writable by: %s",
				strings.Join(lowPrivWriters, ", ")))
		}

		if len(findings) > 0 {
			vulnCount++
			sb.WriteString(fmt.Sprintf("[!] %s (CA: %s)\n", name, strings.Join(cas, ", ")))
			for _, f := range findings {
				sb.WriteString(fmt.Sprintf("    %s\n", f))
			}
			if len(allEKUs) > 0 {
				ekuNames := make([]string, 0, len(allEKUs))
				for _, e := range allEKUs {
					ekuNames = append(ekuNames, adcsResolveEKU(e))
				}
				sb.WriteString(fmt.Sprintf("    EKUs: %s\n", strings.Join(ekuNames, ", ")))
			}
			sb.WriteString("\n")
		}
	}

	if vulnCount == 0 {
		sb.WriteString("No ESC1-ESC4 vulnerabilities found in published templates.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Found %d vulnerable template(s)\n", vulnCount))
	}
	sb.WriteString("\nNote: ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) and ESC8 (HTTP enrollment)\n")
	sb.WriteString("require CA configuration checks not available via LDAP.\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// adcsResolveEKU converts an OID to a human-readable name
func adcsResolveEKU(oid string) string {
	names := map[string]string{
		oidClientAuth:              "Client Authentication",
		oidServerAuth:              "Server Authentication",
		oidPKINITClient:            "PKINIT Client Auth",
		oidSmartCardLogon:          "Smart Card Logon",
		oidAnyPurpose:              "Any Purpose",
		oidCertRequestAgent:        "Certificate Request Agent",
		"1.3.6.1.5.5.7.3.4":        "Secure Email",
		"1.3.6.1.5.5.7.3.8":        "Time Stamping",
		"1.3.6.1.4.1.311.10.3.4":   "EFS Recovery Agent",
		"1.3.6.1.4.1.311.10.3.12":  "Document Signing",
		"1.3.6.1.4.1.311.54.1.2":   "Remote Desktop Auth",
		"1.3.6.1.4.1.311.10.3.4.1": "EFS Data Recovery",
		"1.3.6.1.4.1.311.21.5":     "CA Encryption Certificate",
		"1.3.6.1.4.1.311.10.3.1":   "CTL Signing",
		"1.3.6.1.5.5.7.3.9":        "OCSP Signing",
	}
	if name, ok := names[oid]; ok {
		return name
	}
	return oid
}

func adcsHasAuthEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true // no EKU = any purpose
	}
	for _, eku := range ekus {
		switch eku {
		case oidClientAuth, oidPKINITClient, oidSmartCardLogon, oidAnyPurpose:
			return true
		}
	}
	return false
}

func adcsHasAnyPurposeEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == oidAnyPurpose {
			return true
		}
	}
	return false
}

func adcsHasCertRequestAgentEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == oidCertRequestAgent {
			return true
		}
	}
	return false
}

// --- Security Descriptor Parsing ---

type sdACE struct {
	sid        string
	mask       uint32
	objectGUID []byte
}

// adcsParseEnrollmentPerms extracts SIDs with Certificate-Enrollment or GenericAll rights
func adcsParseEnrollmentPerms(sd []byte) []string {
	aces := adcsParseSD(sd)
	sids := make(map[string]bool)

	for _, ace := range aces {
		if ace.mask&adsGenericAll != 0 {
			sids[ace.sid] = true
			continue
		}
		if ace.mask&adsRightDSControlAccess != 0 {
			if len(ace.objectGUID) == 0 {
				sids[ace.sid] = true // all extended rights
			} else if adcsMatchGUID(ace.objectGUID, enrollmentGUID) {
				sids[ace.sid] = true
			}
		}
	}

	result := make([]string, 0, len(sids))
	for sid := range sids {
		result = append(result, sid)
	}
	return result
}

// adcsParseWritePerms extracts SIDs with write access to the template
func adcsParseWritePerms(sd []byte) []string {
	aces := adcsParseSD(sd)
	sids := make(map[string]bool)

	for _, ace := range aces {
		if ace.mask&adsGenericAll != 0 || ace.mask&adsWriteDACL != 0 || ace.mask&adsWriteOwner != 0 {
			sids[ace.sid] = true
		}
	}

	result := make([]string, 0, len(sids))
	for sid := range sids {
		result = append(result, sid)
	}
	return result
}

// adcsParseSD parses a binary SECURITY_DESCRIPTOR_RELATIVE to extract DACL ACEs
func adcsParseSD(sd []byte) []sdACE {
	if len(sd) < 20 {
		return nil
	}

	// SECURITY_DESCRIPTOR_RELATIVE header (20 bytes):
	// [0]  Revision (1), [1] Sbz1 (1), [2:4] Control (2 LE)
	// [4:8] OffsetOwner, [8:12] OffsetGroup, [12:16] OffsetSacl, [16:20] OffsetDacl

	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset >= len(sd) {
		return nil
	}

	return adcsParseACL(sd, daclOffset)
}

// adcsParseACL parses an ACL at the given offset within the SD buffer
func adcsParseACL(sd []byte, offset int) []sdACE {
	if offset+8 > len(sd) {
		return nil
	}

	// ACL header (8 bytes):
	// [0] Revision, [1] Sbz1, [2:4] AclSize, [4:6] AceCount, [6:8] Sbz2

	aceCount := int(binary.LittleEndian.Uint16(sd[offset+4 : offset+6]))
	aces := make([]sdACE, 0, aceCount)
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
					aces = append(aces, sdACE{sid: sid, mask: mask})
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
						aces = append(aces, sdACE{sid: sid, mask: mask, objectGUID: objectGUID})
					}
				}
			}
		}

		pos += aceSize
	}

	return aces
}

// adcsParseSID converts binary SID to string format S-R-I-S-S-S...
func adcsParseSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subCount := int(b[1])

	if len(b) < 8+subCount*4 {
		return ""
	}

	// Identifier authority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	parts := make([]string, 0, 2+subCount)
	parts = append(parts, fmt.Sprintf("S-%d-%d", revision, authority))

	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		parts = append(parts, strconv.FormatUint(uint64(sub), 10))
	}

	return strings.Join(parts, "-")
}

// guidToBytes converts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to 16-byte mixed-endian binary
func guidToBytes(s string) []byte {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return nil
	}

	b := make([]byte, 16)

	// Data1 (4 bytes LE)
	d1, _ := strconv.ParseUint(parts[0], 16, 32)
	binary.LittleEndian.PutUint32(b[0:4], uint32(d1))

	// Data2 (2 bytes LE)
	d2, _ := strconv.ParseUint(parts[1], 16, 16)
	binary.LittleEndian.PutUint16(b[4:6], uint16(d2))

	// Data3 (2 bytes LE)
	d3, _ := strconv.ParseUint(parts[2], 16, 16)
	binary.LittleEndian.PutUint16(b[6:8], uint16(d3))

	// Data4 (8 bytes BE) — parts[3] + parts[4] concatenated
	d4str := parts[3] + parts[4]
	for i := 0; i < 8 && i*2+1 < len(d4str); i++ {
		val, _ := strconv.ParseUint(d4str[i*2:i*2+2], 16, 8)
		b[8+i] = byte(val)
	}

	return b
}

// adcsMatchGUID compares two 16-byte GUID buffers
func adcsMatchGUID(a, b []byte) bool {
	if len(a) != 16 || len(b) != 16 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// adcsFilterLowPriv filters SID strings to only return low-privilege identities
func adcsFilterLowPriv(sids []string) []string {
	var result []string
	for _, sid := range sids {
		if name, ok := lowPrivSIDMap[sid]; ok {
			result = append(result, name)
			continue
		}
		// Check domain-relative RIDs (S-1-5-21-x-x-x-RID)
		parts := strings.Split(sid, "-")
		if len(parts) >= 5 && parts[0] == "S" && parts[1] == "1" && parts[2] == "5" && parts[3] == "21" {
			rid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
			if err == nil {
				if name, ok := lowPrivRIDMap[uint32(rid)]; ok {
					result = append(result, name)
				}
			}
		}
	}
	return result
}
