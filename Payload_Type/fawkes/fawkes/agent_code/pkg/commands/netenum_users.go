//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

// --- Action: users ---

func netEnumLocalUsers() structs.CommandResult {
	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32
	var users []string

	for {
		ret, _, _ := procNetUserEnum.Call(
			0,
			0,
			uintptr(FILTER_NORMAL_ACCT),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return errorf("Error enumerating local users: NetUserEnum returned %d %s", ret, netApiErrorDesc(ret))
		}

		if buf != 0 {
			entries := unsafe.Slice((*userInfo0)(unsafe.Pointer(buf)), entriesRead)
			for _, entry := range entries {
				if entry.Name != nil {
					users = append(users, windows.UTF16PtrToString(entry.Name))
				}
			}
			procNetApiBufferFree.Call(buf)
			buf = 0
		}

		if ret != ERROR_MORE_DATA {
			break
		}
	}

	var entries []netEnumEntry
	for _, u := range users {
		entries = append(entries, netEnumEntry{Name: u, Type: "local_user"})
	}
	if len(entries) == 0 {
		return successResult("[]")
	}
	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// --- Action: localgroups (enhanced with remote server support) ---

func netEnumLocalGroups(target string) structs.CommandResult {
	serverPtr, err := neGetServerPtr(target)
	if err != nil {
		return errorf("Error: %v", err)
	}

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	type groupEntry struct {
		name    string
		comment string
	}
	var groups []groupEntry

	for {
		ret, _, _ := procNetLocalGroupEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			1,
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return errorf("Error enumerating local groups: NetLocalGroupEnum returned %d %s", ret, netApiErrorDesc(ret))
		}

		if buf != 0 {
			entries := unsafe.Slice((*localGroupInfo1)(unsafe.Pointer(buf)), entriesRead)
			for _, entry := range entries {
				name := ""
				comment := ""
				if entry.Name != nil {
					name = windows.UTF16PtrToString(entry.Name)
				}
				if entry.Comment != nil {
					comment = windows.UTF16PtrToString(entry.Comment)
				}
				groups = append(groups, groupEntry{name: name, comment: comment})
			}
			procNetApiBufferFree.Call(buf)
			buf = 0
		}

		if ret != ERROR_MORE_DATA {
			break
		}
	}

	var entries []netEnumEntry
	for _, g := range groups {
		entries = append(entries, netEnumEntry{Name: g.name, Comment: g.comment, Type: "local_group", Server: target})
	}
	if len(entries) == 0 {
		return successResult("[]")
	}
	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// --- Action: groupmembers (enhanced with remote server + SID type) ---

func netEnumGroupMembers(group, target string) structs.CommandResult {
	if group == "" {
		return errorResult("Error: group name is required for groupmembers/admins action. Use -group <name> or -target <name>.")
	}

	// For groupmembers, target is the group name (backward compat) unless group param is set.
	// When group is explicitly set, target becomes the remote server.
	server := ""
	if group != target && target != "" {
		server = target
	}

	serverPtr, err := neGetServerPtr(server)
	if err != nil {
		return errorf("Error: %v", err)
	}

	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return errorf("Error: %v", err)
	}

	var buf uintptr
	var entriesRead, totalEntries uint32

	// Use level 2 for SID usage type info
	ret, _, _ := procNetLocalGroupGetMem.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		uintptr(unsafe.Pointer(groupPtr)),
		2,
		uintptr(unsafe.Pointer(&buf)),
		MAX_PREFERRED_LEN,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return errorf("NetLocalGroupGetMembers failed with error %d (group: %s)", ret, group)
	}
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(localGroupMembersInfo2{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupMembersInfo2)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		name := ""
		if entry.DomainAndName != nil {
			name = windows.UTF16PtrToString(entry.DomainAndName)
		}
		entries = append(entries, netEnumEntry{
			Name:   name,
			Type:   nlgSidUsageString(entry.SIDUsage),
			Source: group,
			Server: server,
		})
	}

	if len(entries) == 0 {
		return successResult("[]")
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}
	return successResult(string(data))
}

// --- Action: domainusers ---

func netEnumDomainUsers() structs.CommandResult {
	dcName, err := getDomainControllerName()
	if err != nil {
		return errorf("Error: %v", err)
	}

	serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32
	var users []string

	for {
		ret, _, _ := procNetUserEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0,
			uintptr(FILTER_NORMAL_ACCT),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return errorf("Error enumerating domain users from %s: NetUserEnum returned %d %s (hint: use ldap-query -action users for authenticated domain queries)", dcName, ret, netApiErrorDesc(ret))
		}

		if buf != 0 {
			entries := unsafe.Slice((*userInfo0)(unsafe.Pointer(buf)), entriesRead)
			for _, entry := range entries {
				if entry.Name != nil {
					users = append(users, windows.UTF16PtrToString(entry.Name))
				}
			}
			procNetApiBufferFree.Call(buf)
			buf = 0
		}

		if ret != ERROR_MORE_DATA {
			break
		}
	}

	var entries []netEnumEntry
	for _, u := range users {
		entries = append(entries, netEnumEntry{Name: u, Type: "domain_user", Source: dcName})
	}
	if len(entries) == 0 {
		return successResult("[]")
	}
	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// --- Action: domaingroups ---

func netEnumDomainGroups() structs.CommandResult {
	dcName, err := getDomainControllerName()
	if err != nil {
		return errorf("Error: %v", err)
	}

	serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32
	var groups []string

	for {
		ret, _, _ := procNetGroupEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0,
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return errorf("Error enumerating domain groups from %s: NetGroupEnum returned %d %s (hint: use ldap-query -action groups for authenticated domain queries)", dcName, ret, netApiErrorDesc(ret))
		}

		if buf != 0 {
			entries := unsafe.Slice((*groupInfo0)(unsafe.Pointer(buf)), entriesRead)
			for _, entry := range entries {
				if entry.Name != nil {
					groups = append(groups, windows.UTF16PtrToString(entry.Name))
				}
			}
			procNetApiBufferFree.Call(buf)
			buf = 0
		}

		if ret != ERROR_MORE_DATA {
			break
		}
	}

	var entries []netEnumEntry
	for _, g := range groups {
		entries = append(entries, netEnumEntry{Name: g, Type: "domain_group", Source: dcName})
	}
	if len(entries) == 0 {
		return successResult("[]")
	}
	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// --- Action: domaininfo ---

func netEnumDomainInfo() structs.CommandResult {
	out := domainInfoOutput{}

	var dcInfo *domainControllerInfo
	ret, _, _ := procDsGetDcNameW.Call(
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dcInfo)),
	)
	if ret == NERR_Success && dcInfo != nil {
		out.DCName = windows.UTF16PtrToString(dcInfo.DomainControllerName)
		out.DCAddress = windows.UTF16PtrToString(dcInfo.DomainControllerAddress)
		out.Domain = windows.UTF16PtrToString(dcInfo.DomainName)
		out.Forest = windows.UTF16PtrToString(dcInfo.DnsForestName)
		if dcInfo.DcSiteName != nil {
			out.DCSite = windows.UTF16PtrToString(dcInfo.DcSiteName)
		}
		if dcInfo.ClientSiteName != nil {
			out.ClientSite = windows.UTF16PtrToString(dcInfo.ClientSiteName)
		}

		procNetApiBufferFree.Call(uintptr(unsafe.Pointer(dcInfo)))

		dcNameClean := strings.TrimPrefix(out.DCName, "\\\\")
		serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcNameClean)
		var modalsInfo uintptr
		modRet, _, _ := procNetUserModalsGet.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0,
			uintptr(unsafe.Pointer(&modalsInfo)),
		)
		if modRet == NERR_Success && modalsInfo != 0 {
			info := (*userModalsInfo0)(unsafe.Pointer(modalsInfo))
			out.MinPassLen = info.MinPasswdLen
			if info.MaxPasswdAge > 0 {
				out.MaxPassAge = info.MaxPasswdAge / 86400
			}
			out.MinPassAge = info.MinPasswdAge / 86400
			out.PassHistLen = info.PasswordHistLen
			if info.ForceLogoff == 0xFFFFFFFF {
				out.ForceLogoff = "Never"
			} else {
				out.ForceLogoff = fmt.Sprintf("%d seconds", info.ForceLogoff)
			}
			procNetApiBufferFree.Call(modalsInfo)
		}
	} else {
		return errorf("Error: DsGetDcNameW failed (error %d — machine may not be domain-joined)", ret)
	}

	var trustCount uint32
	var trustBuf uintptr
	trustFlags := uint32(DS_DOMAIN_IN_FOREST | DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_DIRECT_INBOUND)
	trustRet, _, _ := procDsEnumDomainTrusts.Call(
		0,
		uintptr(trustFlags),
		uintptr(unsafe.Pointer(&trustBuf)),
		uintptr(unsafe.Pointer(&trustCount)),
	)
	if trustRet == NERR_Success && trustCount > 0 && trustBuf != 0 {
		trusts := unsafe.Slice((*dsDomainTrusts)(unsafe.Pointer(trustBuf)), trustCount)
		for _, t := range trusts {
			e := netEnumEntry{Type: "trust"}
			if t.NetbiosDomainName != nil {
				e.Name = windows.UTF16PtrToString(t.NetbiosDomainName)
			}
			if t.DnsDomainName != nil {
				e.DNS = windows.UTF16PtrToString(t.DnsDomainName)
			}
			e.Flags = describeTrustFlags(t.Flags)
			out.Trusts = append(out.Trusts, e)
		}
		procNetApiBufferFree.Call(trustBuf)
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}
