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

type TrustCommand struct{}

func (c *TrustCommand) Name() string { return "trust" }
func (c *TrustCommand) Description() string {
	return "Enumerate domain and forest trust relationships via LDAP (T1482)"
}

type trustArgs struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`
}

// Trust direction constants
const (
	trustDirectionInbound  = 1
	trustDirectionOutbound = 2
	trustDirectionBidir    = 3
)

// Trust type constants
const (
	trustTypeDownlevel = 1 // Windows NT 4.0 / Samba
	trustTypeUplevel   = 2 // Active Directory
	trustTypeMIT       = 3 // MIT Kerberos realm
)

// Trust attribute flags
const (
	trustAttrNonTransitive       = 0x00000001
	trustAttrUplevelOnly         = 0x00000002
	trustAttrFilterSIDs          = 0x00000004 // SID filtering (quarantine)
	trustAttrForestTransitive    = 0x00000008
	trustAttrCrossOrganization   = 0x00000010
	trustAttrWithinForest        = 0x00000020
	trustAttrTreatAsExternal     = 0x00000040
	trustAttrUsesRC4Encryption   = 0x00000080
	trustAttrUsesAESKeys         = 0x00000100
	trustAttrCrossOrgNoTGTDeleg  = 0x00000200
	trustAttrPIMTrust            = 0x00000400
	trustAttrCrossOrgEnableTGTDe = 0x00000800
)

type trustEntry struct {
	name        string
	partner     string
	flatName    string
	direction   int
	trustType   int
	attributes  int
	sid         string
	dn          string
	whenCreated string
	whenChanged string
}

// trustOutputEntry is a JSON-serializable trust for browser script rendering.
type trustOutputEntry struct {
	Partner     string `json:"partner"`
	FlatName    string `json:"flat_name,omitempty"`
	Direction   string `json:"direction"`
	Type        string `json:"type"`
	Category    string `json:"category"`
	Transitive  string `json:"transitive"`
	Attributes  string `json:"attributes"`
	SID         string `json:"sid,omitempty"`
	WhenCreated string `json:"when_created,omitempty"`
	WhenChanged string `json:"when_changed,omitempty"`
	Risk        string `json:"risk,omitempty"`
}

// trustForestInfo holds forest topology discovered from crossRef objects.
type trustForestInfo struct {
	ForestRoot string   `json:"forest_root"`
	Domains    []string `json:"domains"`
}

func (c *TrustCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> [-username user@domain -password pass]",
			Status:    "error",
			Completed: true,
		}
	}

	var args trustArgs
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

	conn, err := trustConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	if err := trustBind(conn, args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	baseDN, err := trustDetectBaseDN(conn)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error detecting base DN: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return trustEnumerate(conn, baseDN)
}

func trustConnect(args trustArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func trustBind(conn *ldap.Conn, args trustArgs) error {
	if args.Username != "" && args.Password != "" {
		return conn.Bind(args.Username, args.Password)
	}
	return conn.UnauthenticatedBind("")
}

func trustDetectBaseDN(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entries returned")
	}
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("could not detect defaultNamingContext")
	}
	return baseDN, nil
}

// trustTopLevelOutput wraps trust entries with forest topology info.
type trustTopLevelOutput struct {
	Forest *trustForestInfo  `json:"forest,omitempty"`
	Trusts []trustOutputEntry `json:"trusts"`
}

func trustEnumerate(conn *ldap.Conn, baseDN string) structs.CommandResult {
	// Query trustedDomain objects in CN=System,<baseDN>
	systemDN := fmt.Sprintf("CN=System,%s", baseDN)

	req := ldap.NewSearchRequest(systemDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=trustedDomain)",
		[]string{
			"cn", "trustPartner", "flatName", "trustDirection",
			"trustType", "trustAttributes", "securityIdentifier",
			"whenCreated", "whenChanged",
		},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying trustedDomain objects: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Parse entries
	var trusts []trustEntry
	for _, entry := range result.Entries {
		t := trustEntry{
			name:        entry.GetAttributeValue("cn"),
			partner:     entry.GetAttributeValue("trustPartner"),
			flatName:    entry.GetAttributeValue("flatName"),
			dn:          entry.DN,
			whenCreated: entry.GetAttributeValue("whenCreated"),
			whenChanged: entry.GetAttributeValue("whenChanged"),
		}

		if v := entry.GetAttributeValue("trustDirection"); v != "" {
			t.direction, _ = strconv.Atoi(v)
		}
		if v := entry.GetAttributeValue("trustType"); v != "" {
			t.trustType, _ = strconv.Atoi(v)
		}
		if v := entry.GetAttributeValue("trustAttributes"); v != "" {
			t.attributes, _ = strconv.Atoi(v)
		}

		// Parse binary SID
		sidBytes := entry.GetRawAttributeValue("securityIdentifier")
		if len(sidBytes) >= 8 {
			t.sid = trustParseSID(sidBytes)
		}

		trusts = append(trusts, t)
	}

	// Derive current domain from baseDN
	currentDomain := trustDNToDomain(baseDN)

	// Query forest topology from Configuration partition
	forestInfo := trustQueryForestTopology(conn, baseDN)

	if len(trusts) == 0 {
		topLevel := trustTopLevelOutput{Forest: forestInfo}
		data, _ := json.Marshal(topLevel)
		return structs.CommandResult{
			Output:    string(data),
			Status:    "success",
			Completed: true,
		}
	}

	// Build JSON entries with category, transitivity, and risk annotations
	var output []trustOutputEntry
	for _, t := range trusts {
		category := trustCategory(t)
		transitive := trustTransitivity(t)
		risks := trustComputeRisks(t)

		dirStr := trustDirectionStr(t.direction, currentDomain, t.partner)
		e := trustOutputEntry{
			Partner:     t.partner,
			FlatName:    t.flatName,
			Direction:   dirStr,
			Type:        trustTypeStr(t.trustType),
			Category:    category,
			Transitive:  transitive,
			Attributes:  trustAttributesStr(t.attributes),
			SID:         t.sid,
			WhenCreated: trustFormatTimestamp(t.whenCreated),
			WhenChanged: trustFormatTimestamp(t.whenChanged),
		}
		if len(risks) > 0 {
			e.Risk = strings.Join(risks, "; ")
		}
		output = append(output, e)
	}

	topLevel := trustTopLevelOutput{
		Forest: forestInfo,
		Trusts: output,
	}
	data, err := json.Marshal(topLevel)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

// trustCategory determines the trust category based on attributes and type.
func trustCategory(t trustEntry) string {
	if t.attributes&trustAttrWithinForest != 0 {
		return "Intra-Forest"
	}
	if t.attributes&trustAttrForestTransitive != 0 {
		return "Forest"
	}
	if t.attributes&trustAttrTreatAsExternal != 0 {
		return "External (forced)"
	}
	if t.trustType == trustTypeUplevel {
		return "External"
	}
	if t.trustType == trustTypeMIT {
		return "MIT Kerberos"
	}
	if t.trustType == trustTypeDownlevel {
		return "Downlevel"
	}
	return "Other"
}

// trustTransitivity returns whether the trust is transitive and why.
func trustTransitivity(t trustEntry) string {
	if t.attributes&trustAttrNonTransitive != 0 {
		return "Non-transitive"
	}
	if t.attributes&trustAttrWithinForest != 0 {
		return "Transitive (intra-forest)"
	}
	if t.attributes&trustAttrForestTransitive != 0 {
		return "Transitive (forest)"
	}
	// External trusts are non-transitive by default
	if t.trustType == trustTypeUplevel && t.attributes&trustAttrWithinForest == 0 && t.attributes&trustAttrForestTransitive == 0 {
		return "Non-transitive (external)"
	}
	return "Transitive"
}

// trustComputeRisks analyzes a trust entry for security risks.
func trustComputeRisks(t trustEntry) []string {
	var risks []string

	if t.direction == trustDirectionOutbound || t.direction == trustDirectionBidir {
		if t.attributes&trustAttrFilterSIDs == 0 {
			risks = append(risks, "No SID filtering — SID history attacks possible")
		}
		if t.attributes&trustAttrWithinForest != 0 {
			risks = append(risks, "Intra-forest — implicit full trust")
		}
		if t.attributes&trustAttrForestTransitive != 0 && t.attributes&trustAttrFilterSIDs == 0 {
			risks = append(risks, "Forest trust without SID filtering — cross-forest attack possible")
		}
	}

	// RC4-only encryption is weak — AES should be preferred
	if t.attributes&trustAttrUsesRC4Encryption != 0 && t.attributes&trustAttrUsesAESKeys == 0 {
		risks = append(risks, "RC4 encryption only — vulnerable to offline cracking")
	}

	// Selective authentication means the trust requires explicit permissions
	if t.attributes&trustAttrCrossOrganization != 0 {
		// This is actually defensive, so note it rather than flag as risk
		risks = append(risks, "Selective authentication enabled — restricted access")
	}

	// TGT delegation across organizations
	if t.attributes&trustAttrCrossOrgEnableTGTDe != 0 {
		risks = append(risks, "TGT delegation enabled across organizations")
	}

	return risks
}

// trustDirectionStr provides a detailed direction string including domain context.
func trustDirectionStr(dir int, currentDomain, partner string) string {
	switch dir {
	case trustDirectionInbound:
		return fmt.Sprintf("Inbound (%s trusts %s)", partner, currentDomain)
	case trustDirectionOutbound:
		return fmt.Sprintf("Outbound (%s trusts %s)", currentDomain, partner)
	case trustDirectionBidir:
		return "Bidirectional"
	default:
		return fmt.Sprintf("Unknown (%d)", dir)
	}
}

// trustFormatTimestamp formats AD generalized time (20060102150405.0Z) to readable form.
func trustFormatTimestamp(raw string) string {
	if raw == "" {
		return ""
	}
	// AD timestamps use format: 20060102150405.0Z
	raw = strings.TrimSuffix(raw, ".0Z")
	if len(raw) >= 14 {
		return raw[:4] + "-" + raw[4:6] + "-" + raw[6:8] + " " + raw[8:10] + ":" + raw[10:12] + ":" + raw[12:14] + " UTC"
	}
	return raw
}

// trustQueryForestTopology queries crossRef objects from the Configuration partition
// to discover the forest root and all domains in the forest.
func trustQueryForestTopology(conn *ldap.Conn, baseDN string) *trustForestInfo {
	// Build Configuration DN from baseDN: DC=domain,DC=local -> CN=Partitions,CN=Configuration,DC=domain,DC=local
	// Find the forest root by looking at the root domain's baseDN
	configDN := trustBuildConfigDN(baseDN)
	if configDN == "" {
		return nil
	}

	partitionsDN := fmt.Sprintf("CN=Partitions,%s", configDN)

	req := ldap.NewSearchRequest(partitionsDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false,
		"(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=1))", // SYSTEM_FLAG_CR_NTDS_NC
		[]string{"dnsRoot", "nCName", "nETBIOSName", "trustParent"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return nil
	}

	if len(result.Entries) == 0 {
		return nil
	}

	info := &trustForestInfo{}
	for _, entry := range result.Entries {
		dnsRoot := entry.GetAttributeValue("dnsRoot")
		if dnsRoot == "" {
			continue
		}
		info.Domains = append(info.Domains, dnsRoot)

		// The entry with no trustParent (or trustParent pointing to itself) is the forest root
		trustParent := entry.GetAttributeValue("trustParent")
		if trustParent == "" {
			info.ForestRoot = dnsRoot
		}
	}

	// If we didn't find a root via trustParent, use the first domain
	if info.ForestRoot == "" && len(info.Domains) > 0 {
		info.ForestRoot = info.Domains[0]
	}

	return info
}

// trustBuildConfigDN derives CN=Configuration,DC=... from a baseDN.
// For a child domain like DC=north,DC=sevenkingdoms,DC=local, the Configuration
// partition is at the forest root (DC=sevenkingdoms,DC=local), but we try the
// full DN first since LDAP will redirect if needed.
func trustBuildConfigDN(baseDN string) string {
	if baseDN == "" {
		return ""
	}
	return fmt.Sprintf("CN=Configuration,%s", baseDN)
}


func trustTypeStr(t int) string {
	switch t {
	case trustTypeDownlevel:
		return "Downlevel (Windows NT 4.0)"
	case trustTypeUplevel:
		return "Uplevel (Active Directory)"
	case trustTypeMIT:
		return "MIT (Kerberos realm)"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

func trustAttributesStr(attrs int) string {
	if attrs == 0 {
		return "None"
	}

	var flags []string
	if attrs&trustAttrNonTransitive != 0 {
		flags = append(flags, "NON_TRANSITIVE")
	}
	if attrs&trustAttrUplevelOnly != 0 {
		flags = append(flags, "UPLEVEL_ONLY")
	}
	if attrs&trustAttrFilterSIDs != 0 {
		flags = append(flags, "SID_FILTERING")
	}
	if attrs&trustAttrForestTransitive != 0 {
		flags = append(flags, "FOREST_TRANSITIVE")
	}
	if attrs&trustAttrCrossOrganization != 0 {
		flags = append(flags, "CROSS_ORGANIZATION")
	}
	if attrs&trustAttrWithinForest != 0 {
		flags = append(flags, "WITHIN_FOREST")
	}
	if attrs&trustAttrTreatAsExternal != 0 {
		flags = append(flags, "TREAT_AS_EXTERNAL")
	}
	if attrs&trustAttrUsesRC4Encryption != 0 {
		flags = append(flags, "RC4_ENCRYPTION")
	}
	if attrs&trustAttrUsesAESKeys != 0 {
		flags = append(flags, "AES_KEYS")
	}
	if attrs&trustAttrCrossOrgNoTGTDeleg != 0 {
		flags = append(flags, "NO_TGT_DELEGATION")
	}
	if attrs&trustAttrPIMTrust != 0 {
		flags = append(flags, "PIM_TRUST")
	}
	if attrs&trustAttrCrossOrgEnableTGTDe != 0 {
		flags = append(flags, "ENABLE_TGT_DELEGATION")
	}

	if len(flags) == 0 {
		return fmt.Sprintf("0x%X", attrs)
	}
	return strings.Join(flags, " | ")
}

// trustParseSID converts a binary SID to string form (S-1-5-21-...)
func trustParseSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subAuthCount := int(b[1])

	// 6-byte big-endian authority
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthCount; i++ {
		offset := 8 + i*4
		if offset+4 > len(b) {
			break
		}
		subAuth := binary.LittleEndian.Uint32(b[offset : offset+4])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// trustDNToDomain converts DC=north,DC=sevenkingdoms,DC=local to north.sevenkingdoms.local
func trustDNToDomain(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	if len(parts) == 0 {
		return dn
	}
	return strings.Join(parts, ".")
}
