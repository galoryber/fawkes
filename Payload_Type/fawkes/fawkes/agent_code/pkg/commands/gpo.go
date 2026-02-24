package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type GpoCommand struct{}

func (c *GpoCommand) Name() string        { return "gpo" }
func (c *GpoCommand) Description() string { return "Enumerate Group Policy Objects via LDAP (T1615)" }

type gpoArgs struct {
	Action   string `json:"action"`   // list, links, find, all
	Server   string `json:"server"`   // DC IP/hostname
	Port     int    `json:"port"`     // optional (default: 389/636)
	Username string `json:"username"` // LDAP bind user (user@domain)
	Password string `json:"password"` // LDAP bind password
	BaseDN   string `json:"base_dn"`  // optional base DN
	UseTLS   bool   `json:"use_tls"`  // use LDAPS
	Filter   string `json:"filter"`   // optional: filter by GPO name substring
}

// Client-Side Extension GUIDs that indicate interesting GPO settings
var interestingCSEs = map[string]string{
	"{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Scripts (Startup/Shutdown/Logon/Logoff)",
	"{40B6664F-4972-11D1-A7CA-0000F87571E3}": "Scripts (Startup/Shutdown/Logon/Logoff)",
	"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security Settings",
	"{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}": "Software Installation",
	"{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS Recovery",
	"{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Software Restriction Policies",
	"{E437BC1C-AA7D-11D2-A382-00C04F991E27}": "IP Security",
	"{F312195E-3D9D-447A-A3F5-08DFFA24735E}": "Windows Firewall",
	"{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}": "Wireless Group Policy",
	"{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}": "Quarantine (NAP)",
	"{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Audit Policy Configuration",
	"{F3CCC681-B74C-4060-9F26-CD84525DCA2A}": "Audit Policy Configuration (Advanced)",
	"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry (Preferences)",
	"{AADCED64-746C-4633-A97C-D61349046527}": "Drive Mapping (Preferences)",
	"{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}": "Scheduled Tasks (Preferences)",
	"{91FBB303-0CD5-4055-BF42-E512A681B325}": "Scheduled Tasks (Preferences)",
	"{728EE579-943C-4519-9EF7-AB56765798ED}": "Data Sources (Preferences)",
	"{6232C319-91F5-4B8A-9467-E86049C0B340}": "Environment Variables (Preferences)",
	"{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Local Users and Groups (Preferences)",
	"{17D89FEC-5C44-4972-B12D-241CAEF74509}": "Local Users and Groups (Preferences)",
	"{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}": "Network Options (VPN/Dial-up)",
	"{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}": "Network Shares (Preferences)",
}

// gPLink regex: [LDAP://cn={GUID},...;flags]
var gpoLinkRegex = regexp.MustCompile(`\[LDAP://[Cc][Nn]=\{([0-9A-Fa-f-]+)\}[^;]*;(\d+)\]`)

func (c *GpoCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <list|links|find|all> -server <DC> -username <user@domain> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args gpoArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "all"
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

	// Connect
	conn, err := gpoConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	// Bind
	if args.Username != "" && args.Password != "" {
		if err := conn.Bind(args.Username, args.Password); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error binding: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error anonymous bind: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Detect base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = gpoDetectBaseDN(conn)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error detecting base DN: %v. Specify -base_dn manually.", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	var sb strings.Builder
	action := strings.ToLower(args.Action)

	switch action {
	case "list":
		sb.WriteString(gpoListAll(conn, baseDN, args.Filter))
	case "links":
		sb.WriteString(gpoEnumLinks(conn, baseDN, args.Filter))
	case "find":
		sb.WriteString(gpoFindInteresting(conn, baseDN, args.Filter))
	case "all":
		sb.WriteString(gpoListAll(conn, baseDN, args.Filter))
		sb.WriteString("\n")
		sb.WriteString(gpoEnumLinks(conn, baseDN, args.Filter))
		sb.WriteString("\n")
		sb.WriteString(gpoFindInteresting(conn, baseDN, args.Filter))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, links, find, all", action),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func gpoConnect(args gpoArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func gpoDetectBaseDN(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
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
		return "", fmt.Errorf("could not detect base DN")
	}
	return baseDN, nil
}

// gpoListAll lists all GPOs from CN=Policies,CN=System,<baseDN>.
func gpoListAll(conn *ldap.Conn, baseDN string, filter string) string {
	policiesDN := fmt.Sprintf("CN=Policies,CN=System,%s", baseDN)

	attrs := []string{
		"displayName", "name", "gPCFileSysPath", "versionNumber",
		"flags", "whenCreated", "whenChanged",
		"gPCMachineExtensionNames", "gPCUserExtensionNames",
	}

	searchRequest := ldap.NewSearchRequest(
		policiesDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=groupPolicyContainer)",
		attrs,
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return fmt.Sprintf("[!] Error querying GPOs: %v\n", err)
	}

	if len(result.Entries) == 0 {
		return "[*] No Group Policy Objects found\n"
	}

	// Filter by name if requested
	entries := result.Entries
	if filter != "" {
		filterLower := strings.ToLower(filter)
		var filtered []*ldap.Entry
		for _, entry := range entries {
			name := entry.GetAttributeValue("displayName")
			if strings.Contains(strings.ToLower(name), filterLower) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Group Policy Objects (%d found)\n", len(entries)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, entry := range entries {
		displayName := entry.GetAttributeValue("displayName")
		guid := entry.GetAttributeValue("name")
		sysvolPath := entry.GetAttributeValue("gPCFileSysPath")
		version := entry.GetAttributeValue("versionNumber")
		flags := entry.GetAttributeValue("flags")
		created := entry.GetAttributeValue("whenCreated")
		modified := entry.GetAttributeValue("whenChanged")

		sb.WriteString(fmt.Sprintf("\n  [GPO] %s\n", displayName))
		sb.WriteString(fmt.Sprintf("    GUID:       %s\n", guid))
		if sysvolPath != "" {
			sb.WriteString(fmt.Sprintf("    SYSVOL:     %s\n", sysvolPath))
		}

		// Parse version: high 16 bits = user version, low 16 bits = machine version
		if version != "" {
			vNum, _ := strconv.ParseUint(version, 10, 32)
			userVer := vNum >> 16
			machineVer := vNum & 0xFFFF
			sb.WriteString(fmt.Sprintf("    Version:    User=%d, Computer=%d\n", userVer, machineVer))
		}

		// Parse flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled
		sb.WriteString(fmt.Sprintf("    Status:     %s\n", gpoFlagsToString(flags)))

		if created != "" {
			sb.WriteString(fmt.Sprintf("    Created:    %s\n", gpoFormatTime(created)))
		}
		if modified != "" {
			sb.WriteString(fmt.Sprintf("    Modified:   %s\n", gpoFormatTime(modified)))
		}
	}

	return sb.String()
}

// gpoEnumLinks finds all objects with gPLink attributes and maps GPOs to their linked OUs.
func gpoEnumLinks(conn *ldap.Conn, baseDN string, filter string) string {
	// First, build a GPO GUID → display name map
	gpoNames := gpoGetNameMap(conn, baseDN)

	// Search for all objects with gPLink attribute
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 30, false,
		"(gPLink=*)",
		[]string{"distinguishedName", "gPLink"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return fmt.Sprintf("[!] Error querying GPO links: %v\n", err)
	}

	if len(result.Entries) == 0 {
		return "[*] No GPO links found\n"
	}

	// Build a map of GPO GUID → []linked objects with enforcement info
	type gpoLink struct {
		target   string
		enforced bool
		disabled bool
	}
	gpoLinksMap := make(map[string][]gpoLink)

	for _, entry := range result.Entries {
		targetDN := entry.DN
		linkVal := entry.GetAttributeValue("gPLink")
		matches := gpoLinkRegex.FindAllStringSubmatch(linkVal, -1)
		for _, m := range matches {
			guid := strings.ToUpper(m[1])
			flagVal, _ := strconv.Atoi(m[2])
			enforced := flagVal&2 != 0
			disabled := flagVal&1 != 0
			gpoLinksMap[guid] = append(gpoLinksMap[guid], gpoLink{
				target:   targetDN,
				enforced: enforced,
				disabled: disabled,
			})
		}
	}

	// Sort GUIDs for consistent output
	guids := make([]string, 0, len(gpoLinksMap))
	for guid := range gpoLinksMap {
		guids = append(guids, guid)
	}
	sort.Strings(guids)

	filterLower := ""
	if filter != "" {
		filterLower = strings.ToLower(filter)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] GPO Links (%d GPOs linked)\n", len(gpoLinksMap)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, guid := range guids {
		links := gpoLinksMap[guid]
		name := gpoNames[guid]
		if name == "" {
			name = "(Unknown GPO)"
		}

		// Apply filter
		if filterLower != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		sb.WriteString(fmt.Sprintf("\n  [GPO] %s {%s}\n", name, guid))
		for _, link := range links {
			flags := ""
			if link.enforced {
				flags += " [ENFORCED]"
			}
			if link.disabled {
				flags += " [DISABLED]"
			}
			sb.WriteString(fmt.Sprintf("    → %s%s\n", link.target, flags))
		}
	}

	return sb.String()
}

// gpoFindInteresting identifies GPOs with potentially exploitable or interesting settings.
func gpoFindInteresting(conn *ldap.Conn, baseDN string, filter string) string {
	policiesDN := fmt.Sprintf("CN=Policies,CN=System,%s", baseDN)

	attrs := []string{
		"displayName", "name", "flags",
		"gPCMachineExtensionNames", "gPCUserExtensionNames",
	}

	searchRequest := ldap.NewSearchRequest(
		policiesDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=groupPolicyContainer)",
		attrs,
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return fmt.Sprintf("[!] Error querying GPOs: %v\n", err)
	}

	if len(result.Entries) == 0 {
		return "[*] No Group Policy Objects found\n"
	}

	filterLower := ""
	if filter != "" {
		filterLower = strings.ToLower(filter)
	}

	type finding struct {
		gpoName  string
		gpoGUID  string
		category string
		cse      string
	}
	var findings []finding

	for _, entry := range result.Entries {
		displayName := entry.GetAttributeValue("displayName")
		guid := entry.GetAttributeValue("name")

		// Apply filter
		if filterLower != "" && !strings.Contains(strings.ToLower(displayName), filterLower) {
			continue
		}

		// Check machine and user extension names for interesting CSEs
		machineExts := entry.GetAttributeValue("gPCMachineExtensionNames")
		userExts := entry.GetAttributeValue("gPCUserExtensionNames")

		seen := make(map[string]bool)
		for cseGUID, cseName := range interestingCSEs {
			if strings.Contains(machineExts, cseGUID) || strings.Contains(userExts, cseGUID) {
				category := gpoCategorizeFinding(cseName)
				key := displayName + category
				if !seen[key] {
					seen[key] = true
					findings = append(findings, finding{
						gpoName:  displayName,
						gpoGUID:  guid,
						category: category,
						cse:      cseName,
					})
				}
			}
		}
	}

	var sb strings.Builder
	if len(findings) == 0 {
		sb.WriteString("[*] No interesting GPO settings detected\n")
		return sb.String()
	}

	// Group findings by category
	categoryOrder := []string{
		"Scripts & Execution",
		"Security Configuration",
		"Scheduled Tasks",
		"User & Group Management",
		"Credential & Certificate",
		"Network Configuration",
		"Software Deployment",
		"Other",
	}
	categoryFindings := make(map[string][]finding)
	for _, f := range findings {
		categoryFindings[f.category] = append(categoryFindings[f.category], f)
	}

	sb.WriteString(fmt.Sprintf("[*] Interesting GPO Settings (%d findings)\n", len(findings)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, cat := range categoryOrder {
		catFindings := categoryFindings[cat]
		if len(catFindings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n  [%s]\n", cat))
		for _, f := range catFindings {
			sb.WriteString(fmt.Sprintf("    %s\n", f.gpoName))
			sb.WriteString(fmt.Sprintf("      GUID: %s\n", f.gpoGUID))
			sb.WriteString(fmt.Sprintf("      CSE:  %s\n", f.cse))
		}
	}

	return sb.String()
}

// gpoGetNameMap builds a GUID → display name map for all GPOs.
func gpoGetNameMap(conn *ldap.Conn, baseDN string) map[string]string {
	policiesDN := fmt.Sprintf("CN=Policies,CN=System,%s", baseDN)

	searchRequest := ldap.NewSearchRequest(
		policiesDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"name", "displayName"},
		nil,
	)

	result, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return nil
	}

	nameMap := make(map[string]string)
	for _, entry := range result.Entries {
		guid := strings.ToUpper(strings.Trim(entry.GetAttributeValue("name"), "{}"))
		name := entry.GetAttributeValue("displayName")
		nameMap[guid] = name
	}
	return nameMap
}

// gpoFlagsToString converts GPO flags to a human-readable status string.
func gpoFlagsToString(flags string) string {
	if flags == "" {
		return "Enabled"
	}
	n, err := strconv.Atoi(flags)
	if err != nil {
		return flags
	}
	switch n {
	case 0:
		return "Enabled"
	case 1:
		return "User Configuration Disabled"
	case 2:
		return "Computer Configuration Disabled"
	case 3:
		return "All Settings Disabled"
	default:
		return fmt.Sprintf("Unknown (%d)", n)
	}
}

// gpoFormatTime formats AD generalized time (e.g., "20250101120000.0Z") to a readable string.
func gpoFormatTime(adTime string) string {
	// AD generalized time format: YYYYMMDDHHmmss.0Z
	if len(adTime) < 14 {
		return adTime
	}
	t, err := time.Parse("20060102150405", adTime[:14])
	if err != nil {
		return adTime
	}
	return t.Format("2006-01-02 15:04:05 UTC")
}

// gpoCategorizeFinding maps a CSE description to a finding category.
func gpoCategorizeFinding(cseName string) string {
	lower := strings.ToLower(cseName)
	switch {
	case strings.Contains(lower, "script"):
		return "Scripts & Execution"
	case strings.Contains(lower, "security") || strings.Contains(lower, "audit"):
		return "Security Configuration"
	case strings.Contains(lower, "scheduled task"):
		return "Scheduled Tasks"
	case strings.Contains(lower, "users and groups"):
		return "User & Group Management"
	case strings.Contains(lower, "efs") || strings.Contains(lower, "ip security"):
		return "Credential & Certificate"
	case strings.Contains(lower, "firewall") || strings.Contains(lower, "wireless") ||
		strings.Contains(lower, "quarantine") || strings.Contains(lower, "vpn") ||
		strings.Contains(lower, "network"):
		return "Network Configuration"
	case strings.Contains(lower, "software"):
		return "Software Deployment"
	case strings.Contains(lower, "registry") || strings.Contains(lower, "environment") ||
		strings.Contains(lower, "drive map") || strings.Contains(lower, "data source") ||
		strings.Contains(lower, "share"):
		return "Other"
	default:
		return "Other"
	}
}
