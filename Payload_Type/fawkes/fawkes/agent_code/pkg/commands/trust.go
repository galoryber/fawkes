// trust.go implements domain/forest trust enumeration via LDAP.
// Security analysis and formatting helpers are in trust_analysis.go.

package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
		return errorResult("Error: parameters required. Use -server <DC> [-username user@domain -password pass]")
	}

	args, parseErr := unmarshalParams[trustArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer structs.ZeroString(&args.Password)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller IP or hostname)")
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
		return errorf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	if err := trustBind(conn, args); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	baseDN, err := trustDetectBaseDN(conn)
	if err != nil {
		return errorf("Error detecting base DN: %v", err)
	}

	return trustEnumerate(conn, baseDN)
}

func trustConnect(args trustArgs) (*ldap.Conn, error) {
	return ldapDial(args.Server, args.Port, args.UseTLS)
}

func trustBind(conn *ldap.Conn, args trustArgs) error {
	return ldapBindSimple(conn, args.Username, args.Password)
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
	Forest *trustForestInfo   `json:"forest,omitempty"`
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
		return errorf("Error querying trustedDomain objects: %v", err)
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
		return successResult(string(data))
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
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(data))
}

// trustQueryForestTopology queries crossRef objects from the Configuration partition
// to discover the forest root and all domains in the forest.
func trustQueryForestTopology(conn *ldap.Conn, baseDN string) *trustForestInfo {
	configDN := trustBuildConfigDN(baseDN)
	if configDN == "" {
		return nil
	}

	partitionsDN := fmt.Sprintf("CN=Partitions,%s", configDN)

	req := ldap.NewSearchRequest(partitionsDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false,
		"(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))", // SYSTEM_FLAG_CR_NTDS_DOMAIN
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
	seen := make(map[string]bool)
	for _, entry := range result.Entries {
		dnsRoot := entry.GetAttributeValue("dnsRoot")
		if dnsRoot == "" || seen[dnsRoot] {
			continue
		}
		seen[dnsRoot] = true
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
func trustBuildConfigDN(baseDN string) string {
	if baseDN == "" {
		return ""
	}
	return fmt.Sprintf("CN=Configuration,%s", baseDN)
}
