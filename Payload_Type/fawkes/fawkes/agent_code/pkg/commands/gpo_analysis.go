// gpo_analysis.go contains GPO security analysis (find interesting settings)
// and helper/formatting functions. Core enumeration is in gpo.go.

package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

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
