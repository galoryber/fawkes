package commands

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LdapQueryCommand struct{}

func (c *LdapQueryCommand) Name() string        { return "ldap-query" }
func (c *LdapQueryCommand) Description() string { return "Query Active Directory via LDAP" }

type ldapQueryArgs struct {
	Action     string   `json:"action"`
	Filter     string   `json:"filter"`
	Server     string   `json:"server"`
	Port       int      `json:"port"`
	BaseDN     string   `json:"base_dn"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Attributes []string `json:"attributes"`
	Limit      int      `json:"limit"`
	UseTLS     bool     `json:"use_tls"`
}

// Preset queries for common red team actions
var presetQueries = map[string]struct {
	filter     string
	attributes []string
	desc       string
}{
	"users": {
		filter:     "(&(objectCategory=person)(objectClass=user))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf", "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "description"},
		desc:       "All domain users",
	},
	"computers": {
		filter:     "(objectClass=computer)",
		attributes: []string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp", "description"},
		desc:       "All domain computers",
	},
	"groups": {
		filter:     "(objectClass=group)",
		attributes: []string{"cn", "description", "member", "memberOf", "groupType"},
		desc:       "All domain groups",
	},
	"domain-admins": {
		filter:     "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,%s))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "displayName", "lastLogonTimestamp", "pwdLastSet"},
		desc:       "Domain admin accounts (recursive group membership)",
	},
	"spns": {
		filter:     "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
		attributes: []string{"sAMAccountName", "servicePrincipalName", "pwdLastSet", "lastLogonTimestamp", "userAccountControl"},
		desc:       "Kerberoastable accounts (users with SPNs)",
	},
	"asrep": {
		filter:     "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		attributes: []string{"sAMAccountName", "userPrincipalName", "userAccountControl", "pwdLastSet"},
		desc:       "AS-REP roastable accounts (pre-auth disabled)",
	},
}

func (c *LdapQueryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <users|computers|groups|domain-admins|spns|asrep|dacl|query> -server <DC>",
			Status:    "error",
			Completed: true,
		}
	}

	var args ldapQueryArgs
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

	if args.Limit <= 0 {
		args.Limit = 100
	}
	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	// Validate dacl action requires filter (target object name)
	if strings.ToLower(args.Action) == "dacl" && args.Filter == "" {
		return structs.CommandResult{
			Output:    "Error: -filter parameter required for dacl action — specify the target object (sAMAccountName, CN, or full DN)",
			Status:    "error",
			Completed: true,
		}
	}

	// Connect to LDAP
	conn, err := ldapConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	// Bind (authenticate)
	if err := ldapBind(conn, args); err != nil {
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

	// Handle dacl action separately (requires binary attribute parsing)
	if strings.ToLower(args.Action) == "dacl" {
		return ldapQueryDACL(conn, args, baseDN)
	}

	// Resolve filter and attributes
	filter, attributes, desc := resolveQuery(args, baseDN)
	if filter == "" {
		return structs.CommandResult{
			Output:    "Error: action must be one of: users, computers, groups, domain-admins, spns, asrep, dacl, query. For 'query', provide -filter. For 'dacl', provide -filter with target object name.",
			Status:    "error",
			Completed: true,
		}
	}

	// Execute search — use SizeLimit=0 with paging to avoid "Size Limit Exceeded"
	// errors from AD, then truncate client-side
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,  // let paging handle size
		30, // time limit in seconds
		false,
		filter,
		attributes,
		nil,
	)

	pagingSize := uint32(args.Limit)
	if pagingSize > 500 {
		pagingSize = 500
	}
	result, err := conn.SearchWithPaging(searchRequest, pagingSize)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing LDAP search: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Truncate to requested limit
	totalFound := len(result.Entries)
	if totalFound > args.Limit {
		result.Entries = result.Entries[:args.Limit]
	}

	// Format output
	output := formatLDAPResults(result, args.Action, desc, baseDN, filter, totalFound)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func ldapConnect(args ldapQueryArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func ldapBind(conn *ldap.Conn, args ldapQueryArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	// Anonymous bind
	return conn.UnauthenticatedBind("")
}

func detectBaseDN(conn *ldap.Conn) (string, error) {
	// Query RootDSE to get defaultNamingContext
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entries returned")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = result.Entries[0].GetAttributeValue("rootDomainNamingContext")
	}
	if baseDN == "" {
		return "", fmt.Errorf("could not detect base DN from RootDSE")
	}

	return baseDN, nil
}

func resolveQuery(args ldapQueryArgs, baseDN string) (string, []string, string) {
	action := strings.ToLower(args.Action)

	if action == "query" {
		if args.Filter == "" {
			return "", nil, ""
		}
		attrs := args.Attributes
		if len(attrs) == 0 {
			attrs = []string{"*"}
		}
		return args.Filter, attrs, "Custom query"
	}

	preset, ok := presetQueries[action]
	if !ok {
		return "", nil, ""
	}

	filter := preset.filter
	// domain-admins needs baseDN substitution for the group DN
	if action == "domain-admins" {
		filter = fmt.Sprintf(filter, baseDN)
	}

	attributes := preset.attributes
	if len(args.Attributes) > 0 {
		attributes = args.Attributes
	}

	return filter, attributes, preset.desc
}

func formatLDAPResults(result *ldap.SearchResult, action, desc, baseDN, filter string, count int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("LDAP Query: %s\n", desc))
	sb.WriteString(fmt.Sprintf("Base DN: %s\n", baseDN))
	sb.WriteString(fmt.Sprintf("Filter: %s\n", filter))
	sb.WriteString(fmt.Sprintf("Results: %d\n", count))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for i, entry := range result.Entries {
		sb.WriteString(fmt.Sprintf("\n[%d] %s\n", i+1, entry.DN))
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				sb.WriteString(fmt.Sprintf("    %-30s %s\n", attr.Name+":", attr.Values[0]))
			} else if len(attr.Values) > 1 {
				sb.WriteString(fmt.Sprintf("    %s:\n", attr.Name))
				for _, v := range attr.Values {
					sb.WriteString(fmt.Sprintf("      - %s\n", v))
				}
			}
		}
	}

	return sb.String()
}

// ldapQueryDACL queries the DACL (access control list) of a specific AD object
// and displays who has what permissions. Uses the -filter parameter as the target
// object name (sAMAccountName, CN, or full DN).
func ldapQueryDACL(conn *ldap.Conn, args ldapQueryArgs, baseDN string) structs.CommandResult {
	target := args.Filter
	if target == "" {
		return structs.CommandResult{
			Output:    "Error: -filter parameter required — specify the target object (sAMAccountName, CN, or full DN)",
			Status:    "error",
			Completed: true,
		}
	}

	// Resolve target to DN
	targetDN, err := ldapResolveDN(conn, target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target '%s': %v", target, err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying nTSecurityDescriptor: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(result.Entries) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: object not found: %s", targetDN),
			Status:    "error",
			Completed: true,
		}
	}

	sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sd) < 20 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: nTSecurityDescriptor too short or not returned (length %d). May need elevated privileges.", len(sd)),
			Status:    "error",
			Completed: true,
		}
	}

	objClass := result.Entries[0].GetAttributeValues("objectClass")

	// Parse the security descriptor
	aces := daclParseSD(sd)

	// Build SID resolution cache
	sidCache := daclResolveSIDs(conn, aces, baseDN)

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] DACL Enumeration (T1069)\n"))
	sb.WriteString(fmt.Sprintf("[+] Target: %s\n", targetDN))
	sb.WriteString(fmt.Sprintf("[+] Object Class: %s\n", strings.Join(objClass, ", ")))
	sb.WriteString(fmt.Sprintf("[+] ACE Count: %d\n", len(aces)))

	// Parse owner if present
	ownerOff := int(binary.LittleEndian.Uint32(sd[4:8]))
	if ownerOff > 0 && ownerOff+8 <= len(sd) {
		ownerSID := adcsParseSID(sd[ownerOff:])
		ownerName := sidCache[ownerSID]
		if ownerName == "" {
			ownerName = ownerSID
		}
		sb.WriteString(fmt.Sprintf("[+] Owner: %s\n", ownerName))
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")

	// Categorize ACEs by risk
	var dangerous, notable, standard []string

	for _, ace := range aces {
		principal := sidCache[ace.sid]
		if principal == "" {
			principal = ace.sid
		}

		perms := daclDescribePermissions(ace.mask, ace.aceType, ace.objectGUID)
		risk := daclAssessRisk(ace.mask, ace.aceType, ace.sid, ace.objectGUID)

		line := fmt.Sprintf("  %-40s %s", principal, perms)

		switch risk {
		case "dangerous":
			dangerous = append(dangerous, fmt.Sprintf("[!] %s", line))
		case "notable":
			notable = append(notable, fmt.Sprintf("[*] %s", line))
		default:
			standard = append(standard, fmt.Sprintf("    %s", line))
		}
	}

	if len(dangerous) > 0 {
		sb.WriteString("\n=== DANGEROUS PERMISSIONS (attack targets) ===\n")
		for _, line := range dangerous {
			sb.WriteString(line + "\n")
		}
	}

	if len(notable) > 0 {
		sb.WriteString("\n=== NOTABLE PERMISSIONS ===\n")
		for _, line := range notable {
			sb.WriteString(line + "\n")
		}
	}

	if len(standard) > 0 {
		sb.WriteString("\n=== STANDARD PERMISSIONS ===\n")
		for _, line := range standard {
			sb.WriteString(line + "\n")
		}
	}

	if len(dangerous) > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] Found %d dangerous ACE(s) — these principals can modify this object.\n", len(dangerous)))
		sb.WriteString("[!] Potential attacks: RBCD (set-rbcd), Shadow Credentials, password change, SPN modification\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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

// daclSIDToBytes converts a string SID (S-1-5-21-...) to binary format
func daclSIDToBytes(sid string) []byte {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return nil
	}

	revision := 0
	fmt.Sscanf(parts[1], "%d", &revision)

	authority := uint64(0)
	fmt.Sscanf(parts[2], "%d", &authority)

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
		subAuth := uint32(0)
		fmt.Sscanf(parts[3+i], "%d", &subAuth)
		binary.LittleEndian.PutUint32(result[8+i*4:], subAuth)
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
	rid := uint32(0)
	fmt.Sscanf(lastPart, "%d", &rid)

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
