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
	name       string
	partner    string
	flatName   string
	direction  int
	trustType  int
	attributes int
	sid        string
	dn         string
}

// trustOutputEntry is a JSON-serializable trust for browser script rendering.
type trustOutputEntry struct {
	Partner    string `json:"partner"`
	FlatName   string `json:"flat_name,omitempty"`
	Direction  string `json:"direction"`
	Type       string `json:"type"`
	Category   string `json:"category"`
	Attributes string `json:"attributes"`
	SID        string `json:"sid,omitempty"`
	Risk       string `json:"risk,omitempty"`
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
			name:     entry.GetAttributeValue("cn"),
			partner:  entry.GetAttributeValue("trustPartner"),
			flatName: entry.GetAttributeValue("flatName"),
			dn:       entry.DN,
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

	if len(trusts) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	// Build JSON entries with category and risk annotations
	var output []trustOutputEntry
	for _, t := range trusts {
		category := "Other"
		if t.attributes&trustAttrWithinForest != 0 {
			category = "Intra-Forest"
		} else if t.attributes&trustAttrForestTransitive != 0 {
			category = "Forest"
		} else if t.trustType == trustTypeUplevel {
			category = "External"
		}

		// Compute risk
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

		dirStr := trustDirectionSimple(t.direction)
		e := trustOutputEntry{
			Partner:    t.partner,
			FlatName:   t.flatName,
			Direction:  dirStr,
			Type:       trustTypeStr(t.trustType),
			Category:   category,
			Attributes: trustAttributesStr(t.attributes),
			SID:        t.sid,
		}
		if len(risks) > 0 {
			e.Risk = strings.Join(risks, "; ")
		}
		output = append(output, e)
	}

	_ = currentDomain // used for direction detail if needed

	data, err := json.Marshal(output)
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

func trustDirectionSimple(dir int) string {
	switch dir {
	case trustDirectionInbound:
		return "Inbound"
	case trustDirectionOutbound:
		return "Outbound"
	case trustDirectionBidir:
		return "Bidirectional"
	default:
		return fmt.Sprintf("Unknown (%d)", dir)
	}
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
