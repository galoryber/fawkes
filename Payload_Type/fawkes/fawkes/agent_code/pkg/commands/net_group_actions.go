package commands

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

func ngList(conn *ldap.Conn, baseDN string) structs.CommandResult {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=group)",
		[]string{"cn", "description", "groupType", "member"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return errorf("Error searching groups: %v", err)
	}

	domain := trustDNToDomain(baseDN)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Domain Groups — %s (%d found)\n", domain, len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Sort by name
	sort.Slice(result.Entries, func(i, j int) bool {
		return strings.ToLower(result.Entries[i].GetAttributeValue("cn")) <
			strings.ToLower(result.Entries[j].GetAttributeValue("cn"))
	})

	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("cn")
		desc := entry.GetAttributeValue("description")
		members := entry.GetAttributeValues("member")
		gType := entry.GetAttributeValue("groupType")

		typeStr := ngGroupTypeStr(gType)
		sb.WriteString(fmt.Sprintf("%-40s  %s  Members: %d", name, typeStr, len(members)))
		if desc != "" {
			sb.WriteString(fmt.Sprintf("  — %s", desc))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

// ngMembers lists members of a specific group (recursive)
func ngMembers(conn *ldap.Conn, baseDN, groupName string) structs.CommandResult {
	// First find the group DN
	groupDN, err := ngFindGroupDN(conn, baseDN, groupName)
	if err != nil {
		return errorf("Error finding group %q: %v", groupName, err)
	}

	// Recursive member query using LDAP_MATCHING_RULE_IN_CHAIN
	filter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(groupDN))

	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"sAMAccountName", "objectClass", "userAccountControl", "description", "memberOf"},
		nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return errorf("Error querying members: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Members of %q (recursive) — %d found\n", groupName, len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	var users, computers, groups []string
	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		classes := entry.GetAttributeValues("objectClass")
		uac := entry.GetAttributeValue("userAccountControl")

		disabled := false
		if uacVal, err := strconv.ParseInt(uac, 10, 64); err == nil {
			disabled = uacVal&0x2 != 0
		}

		suffix := ""
		if disabled {
			suffix = " [DISABLED]"
		}

		if ngContainsClass(classes, "computer") {
			computers = append(computers, name+suffix)
		} else if ngContainsClass(classes, "group") {
			groups = append(groups, name+suffix)
		} else {
			users = append(users, name+suffix)
		}
	}

	sort.Strings(users)
	sort.Strings(computers)
	sort.Strings(groups)

	if len(users) > 0 {
		sb.WriteString(fmt.Sprintf("Users (%d):\n", len(users)))
		for _, u := range users {
			sb.WriteString(fmt.Sprintf("  - %s\n", u))
		}
		sb.WriteString("\n")
	}

	if len(computers) > 0 {
		sb.WriteString(fmt.Sprintf("Computers (%d):\n", len(computers)))
		for _, c := range computers {
			sb.WriteString(fmt.Sprintf("  - %s\n", c))
		}
		sb.WriteString("\n")
	}

	if len(groups) > 0 {
		sb.WriteString(fmt.Sprintf("Nested Groups (%d):\n", len(groups)))
		for _, g := range groups {
			sb.WriteString(fmt.Sprintf("  - %s\n", g))
		}
		sb.WriteString("\n")
	}

	if len(result.Entries) == 0 {
		sb.WriteString("No members found.\n")
	}

	return successResult(sb.String())
}

// ngUserGroups finds all groups a user belongs to (recursive)
func ngUserGroups(conn *ldap.Conn, baseDN, userName string) structs.CommandResult {
	// Find the user first
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(userName))
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 10, false, filter,
		[]string{"sAMAccountName", "distinguishedName", "memberOf"},
		nil)

	result, err := conn.Search(req)
	if err != nil {
		return errorf("Error finding user %q: %v", userName, err)
	}

	if len(result.Entries) == 0 {
		return errorf("User %q not found", userName)
	}

	userDN := result.Entries[0].GetAttributeValue("distinguishedName")

	// Now find all groups this user is a member of (recursive)
	groupFilter := fmt.Sprintf("(member:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(userDN))
	groupReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, groupFilter,
		[]string{"cn", "groupType", "description"},
		nil)

	groupResult, err := conn.SearchWithPaging(groupReq, 100)
	if err != nil {
		return errorf("Error querying groups for %q: %v", userName, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Group Memberships for %q — %d groups\n", userName, len(groupResult.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Separate privileged and normal groups
	var privGroups, normalGroups []string
	privSet := make(map[string]bool)
	for _, pg := range privilegedGroups {
		privSet[strings.ToLower(pg)] = true
	}

	for _, entry := range groupResult.Entries {
		name := entry.GetAttributeValue("cn")
		gType := ngGroupTypeStr(entry.GetAttributeValue("groupType"))
		desc := entry.GetAttributeValue("description")

		line := fmt.Sprintf("%s  %s", name, gType)
		if desc != "" {
			line += fmt.Sprintf("  — %s", desc)
		}

		if privSet[strings.ToLower(name)] {
			privGroups = append(privGroups, line)
		} else {
			normalGroups = append(normalGroups, line)
		}
	}

	sort.Strings(privGroups)
	sort.Strings(normalGroups)

	if len(privGroups) > 0 {
		sb.WriteString(fmt.Sprintf("[!] PRIVILEGED Groups (%d):\n", len(privGroups)))
		for _, g := range privGroups {
			sb.WriteString(fmt.Sprintf("  * %s\n", g))
		}
		sb.WriteString("\n")
	}

	if len(normalGroups) > 0 {
		sb.WriteString(fmt.Sprintf("Other Groups (%d):\n", len(normalGroups)))
		for _, g := range normalGroups {
			sb.WriteString(fmt.Sprintf("  - %s\n", g))
		}
	}

	if len(groupResult.Entries) == 0 {
		sb.WriteString("User has no group memberships (besides primary group).\n")
	}

	return successResult(sb.String())
}

// ngPrivileged finds all privileged groups and their members
func ngPrivileged(conn *ldap.Conn, baseDN string) structs.CommandResult {
	domain := trustDNToDomain(baseDN)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Privileged Group Enumeration — %s\n", domain))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	totalMembers := 0
	for _, groupName := range privilegedGroups {
		// Find the group
		filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
		req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			1, 10, false, filter,
			[]string{"cn", "distinguishedName"},
			nil)

		result, err := conn.Search(req)
		if err != nil || len(result.Entries) == 0 {
			continue // Group doesn't exist in this domain
		}

		groupDN := result.Entries[0].DN

		// Get recursive members
		memberFilter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(groupDN))
		memberReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, memberFilter,
			[]string{"sAMAccountName", "objectClass", "userAccountControl"},
			nil)

		memberResult, err := conn.SearchWithPaging(memberReq, 100)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s — error querying members\n", groupName))
			continue
		}

		if len(memberResult.Entries) == 0 {
			continue // Empty group, skip
		}

		sb.WriteString(fmt.Sprintf("%s (%d members)\n", groupName, len(memberResult.Entries)))
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		for _, entry := range memberResult.Entries {
			name := entry.GetAttributeValue("sAMAccountName")
			classes := entry.GetAttributeValues("objectClass")
			uac := entry.GetAttributeValue("userAccountControl")

			typeStr := "user"
			if ngContainsClass(classes, "computer") {
				typeStr = "computer"
			} else if ngContainsClass(classes, "group") {
				typeStr = "group"
			}

			disabled := ""
			if uacVal, err := strconv.ParseInt(uac, 10, 64); err == nil && uacVal&0x2 != 0 {
				disabled = " [DISABLED]"
			}

			sb.WriteString(fmt.Sprintf("  - %s (%s)%s\n", name, typeStr, disabled))
		}
		sb.WriteString("\n")
		totalMembers += len(memberResult.Entries)
	}

	if totalMembers == 0 {
		sb.WriteString("No privileged group members found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Total privileged accounts: %d\n", totalMembers))
	}

	return successResult(sb.String())
}

// ngFindGroupDN finds the DN of a group by name
