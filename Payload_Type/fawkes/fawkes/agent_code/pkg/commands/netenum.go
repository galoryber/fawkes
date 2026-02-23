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

type NetEnumCommand struct{}

func (c *NetEnumCommand) Name() string {
	return "net-enum"
}

func (c *NetEnumCommand) Description() string {
	return "Enumerate users, groups, and domain information via Win32 API"
}

type netEnumArgs struct {
	Action string `json:"action"`
	Target string `json:"target"`
}

var (
	netapi32NE              = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum         = netapi32NE.NewProc("NetUserEnum")
	procNetLocalGroupEnum   = netapi32NE.NewProc("NetLocalGroupEnum")
	procNetLocalGroupGetMem = netapi32NE.NewProc("NetLocalGroupGetMembers")
	procNetGroupEnum        = netapi32NE.NewProc("NetGroupEnum")
	procNetApiBufferFree    = netapi32NE.NewProc("NetApiBufferFree")
	procDsGetDcNameW        = netapi32NE.NewProc("DsGetDcNameW")
	procNetUserModalsGet    = netapi32NE.NewProc("NetUserModalsGet")
	procDsEnumDomainTrusts  = netapi32NE.NewProc("DsEnumerateDomainTrustsW")
)

const (
	NERR_Success       = 0
	ERROR_MORE_DATA    = 234
	MAX_PREFERRED_LEN  = 0xFFFFFFFF
	FILTER_NORMAL_ACCT = 0x0002
	// DS_DOMAIN_TRUSTS flags
	DS_DOMAIN_IN_FOREST     = 0x0001
	DS_DOMAIN_DIRECT_OUTBOUND = 0x0002
	DS_DOMAIN_TREE_ROOT     = 0x0004
	DS_DOMAIN_PRIMARY       = 0x0008
	DS_DOMAIN_NATIVE_MODE   = 0x0010
	DS_DOMAIN_DIRECT_INBOUND = 0x0020
)

// USER_INFO_0 - just the username
type userInfo0 struct {
	Name *uint16
}

// LOCALGROUP_INFO_1 - group name + comment
type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

// LOCALGROUP_MEMBERS_INFO_3 - member name with domain prefix
type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

// GROUP_INFO_0 - just the group name
type groupInfo0 struct {
	Name *uint16
}

// DOMAIN_CONTROLLER_INFO
type domainControllerInfo struct {
	DomainControllerName    *uint16
	DomainControllerAddress *uint16
	DomainControllerAddrType uint32
	DomainGuid              [16]byte
	DomainName              *uint16
	DnsForestName           *uint16
	Flags                   uint32
	DcSiteName              *uint16
	ClientSiteName          *uint16
}

// USER_MODALS_INFO_0 - account policy
type userModalsInfo0 struct {
	MinPasswdLen    uint32
	MaxPasswdAge    uint32
	MinPasswdAge    uint32
	ForceLogoff     uint32
	PasswordHistLen uint32
}

// DS_DOMAIN_TRUSTS structure
type dsDomainTrusts struct {
	NetbiosDomainName *uint16
	DnsDomainName     *uint16
	Flags             uint32
	ParentIndex       uint32
	TrustType         uint32
	TrustAttributes   uint32
	DomainSid         uintptr
	DomainGuid        [16]byte
}

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args netEnumArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action). Use: users, localgroups, groupmembers, domainusers, domaingroups, domaininfo",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "users":
		return netEnumLocalUsers()
	case "localgroups":
		return netEnumLocalGroups()
	case "groupmembers":
		return netEnumGroupMembers(args.Target)
	case "domainusers":
		return netEnumDomainUsers()
	case "domaingroups":
		return netEnumDomainGroups()
	case "domaininfo":
		return netEnumDomainInfo()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: users, localgroups, groupmembers, domainusers, domaingroups, domaininfo", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// getDomainControllerName returns the DC name for domain-level queries, or empty string if not domain-joined.
func getDomainControllerName() (string, error) {
	var dcInfo *domainControllerInfo
	ret, _, _ := procDsGetDcNameW.Call(
		0, // local computer
		0, // domain name (NULL = primary domain)
		0, // domain GUID
		0, // site name
		0, // flags
		uintptr(unsafe.Pointer(&dcInfo)),
	)
	if ret != NERR_Success {
		return "", fmt.Errorf("DsGetDcNameW failed with error %d (machine may not be domain-joined)", ret)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(dcInfo)))

	dcName := windows.UTF16PtrToString(dcInfo.DomainControllerName)
	// Remove leading backslashes
	dcName = strings.TrimPrefix(dcName, "\\\\")
	return dcName, nil
}

func netEnumLocalUsers() structs.CommandResult {
	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	var users []string

	for {
		ret, _, _ := procNetUserEnum.Call(
			0, // local server
			0, // level 0 (USER_INFO_0)
			uintptr(FILTER_NORMAL_ACCT),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating local users: NetUserEnum returned %d", ret),
				Status:    "error",
				Completed: true,
			}
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Local Users (%d):\n", len(users)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, u := range users {
		sb.WriteString(u + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netEnumLocalGroups() structs.CommandResult {
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
			0, // local server
			1, // level 1 (LOCALGROUP_INFO_1)
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating local groups: NetLocalGroupEnum returned %d", ret),
				Status:    "error",
				Completed: true,
			}
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Local Groups (%d):\n", len(groups)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	for _, g := range groups {
		if g.comment != "" {
			sb.WriteString(fmt.Sprintf("%-30s  %s\n", g.name, g.comment))
		} else {
			sb.WriteString(g.name + "\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netEnumGroupMembers(group string) structs.CommandResult {
	if group == "" {
		return structs.CommandResult{
			Output:    "Error: target (group name) is required for groupmembers action",
			Status:    "error",
			Completed: true,
		}
	}

	groupPtr, err := syscall.UTF16PtrFromString(group)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error converting group name: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	var members []string

	for {
		ret, _, _ := procNetLocalGroupGetMem.Call(
			0, // local server
			uintptr(unsafe.Pointer(groupPtr)),
			3, // level 3 (LOCALGROUP_MEMBERS_INFO_3 — domain\user format)
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating members of '%s': NetLocalGroupGetMembers returned %d", group, ret),
				Status:    "error",
				Completed: true,
			}
		}

		if buf != 0 {
			entries := unsafe.Slice((*localGroupMembersInfo3)(unsafe.Pointer(buf)), entriesRead)
			for _, entry := range entries {
				if entry.DomainAndName != nil {
					members = append(members, windows.UTF16PtrToString(entry.DomainAndName))
				}
			}
			procNetApiBufferFree.Call(buf)
			buf = 0
		}

		if ret != ERROR_MORE_DATA {
			break
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Members of '%s' (%d):\n", group, len(members)))
	sb.WriteString(strings.Repeat("-", 50) + "\n")
	for _, m := range members {
		sb.WriteString(m + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainUsers() structs.CommandResult {
	dcName, err := getDomainControllerName()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	var users []string

	for {
		ret, _, _ := procNetUserEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0, // level 0
			uintptr(FILTER_NORMAL_ACCT),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating domain users from %s: NetUserEnum returned %d", dcName, ret),
				Status:    "error",
				Completed: true,
			}
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Domain Users on %s (%d):\n", dcName, len(users)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, u := range users {
		sb.WriteString(u + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainGroups() structs.CommandResult {
	dcName, err := getDomainControllerName()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	var groups []string

	for {
		ret, _, _ := procNetGroupEnum.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0, // level 0 (GROUP_INFO_0)
			uintptr(unsafe.Pointer(&buf)),
			uintptr(MAX_PREFERRED_LEN),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if ret != NERR_Success && ret != ERROR_MORE_DATA {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating domain groups from %s: NetGroupEnum returned %d", dcName, ret),
				Status:    "error",
				Completed: true,
			}
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Domain Groups on %s (%d):\n", dcName, len(groups)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, g := range groups {
		sb.WriteString(g + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainInfo() structs.CommandResult {
	var sb strings.Builder

	// 1. Domain controller info via DsGetDcNameW
	var dcInfo *domainControllerInfo
	ret, _, _ := procDsGetDcNameW.Call(
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dcInfo)),
	)
	if ret == NERR_Success && dcInfo != nil {
		dcName := windows.UTF16PtrToString(dcInfo.DomainControllerName)
		dcAddr := windows.UTF16PtrToString(dcInfo.DomainControllerAddress)
		domainName := windows.UTF16PtrToString(dcInfo.DomainName)
		forestName := windows.UTF16PtrToString(dcInfo.DnsForestName)
		dcSite := ""
		clientSite := ""
		if dcInfo.DcSiteName != nil {
			dcSite = windows.UTF16PtrToString(dcInfo.DcSiteName)
		}
		if dcInfo.ClientSiteName != nil {
			clientSite = windows.UTF16PtrToString(dcInfo.ClientSiteName)
		}

		sb.WriteString("Domain Controller:\n")
		sb.WriteString(fmt.Sprintf("  DC Name:     %s\n", dcName))
		sb.WriteString(fmt.Sprintf("  DC Address:  %s\n", dcAddr))
		sb.WriteString(fmt.Sprintf("  Domain:      %s\n", domainName))
		sb.WriteString(fmt.Sprintf("  Forest:      %s\n", forestName))
		if dcSite != "" {
			sb.WriteString(fmt.Sprintf("  DC Site:     %s\n", dcSite))
		}
		if clientSite != "" {
			sb.WriteString(fmt.Sprintf("  Client Site: %s\n", clientSite))
		}
		sb.WriteString("\n")

		procNetApiBufferFree.Call(uintptr(unsafe.Pointer(dcInfo)))

		// 2. Account policy via NetUserModalsGet (query the DC)
		dcNameClean := strings.TrimPrefix(dcName, "\\\\")
		serverPtr, _ := syscall.UTF16PtrFromString("\\\\" + dcNameClean)
		var modalsInfo uintptr
		modRet, _, _ := procNetUserModalsGet.Call(
			uintptr(unsafe.Pointer(serverPtr)),
			0, // level 0
			uintptr(unsafe.Pointer(&modalsInfo)),
		)
		if modRet == NERR_Success && modalsInfo != 0 {
			info := (*userModalsInfo0)(unsafe.Pointer(modalsInfo))
			sb.WriteString("Domain Account Policy:\n")
			sb.WriteString(fmt.Sprintf("  Min Password Length:   %d\n", info.MinPasswdLen))
			maxAgeDays := uint32(0)
			if info.MaxPasswdAge > 0 {
				maxAgeDays = info.MaxPasswdAge / 86400
			}
			sb.WriteString(fmt.Sprintf("  Max Password Age:      %d days\n", maxAgeDays))
			minAgeDays := info.MinPasswdAge / 86400
			sb.WriteString(fmt.Sprintf("  Min Password Age:      %d days\n", minAgeDays))
			sb.WriteString(fmt.Sprintf("  Password History Len:  %d\n", info.PasswordHistLen))
			if info.ForceLogoff == 0xFFFFFFFF {
				sb.WriteString("  Force Logoff:          Never\n")
			} else {
				sb.WriteString(fmt.Sprintf("  Force Logoff:          %d seconds\n", info.ForceLogoff))
			}
			sb.WriteString("\n")
			procNetApiBufferFree.Call(modalsInfo)
		}
	} else {
		sb.WriteString(fmt.Sprintf("Domain Controller: (not available, error %d — machine may not be domain-joined)\n\n", ret))
	}

	// 3. Domain trusts via DsEnumerateDomainTrustsW
	var trustCount uint32
	var trustBuf uintptr
	trustFlags := uint32(DS_DOMAIN_IN_FOREST | DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_DIRECT_INBOUND)
	trustRet, _, _ := procDsEnumDomainTrusts.Call(
		0, // local server
		uintptr(trustFlags),
		uintptr(unsafe.Pointer(&trustBuf)),
		uintptr(unsafe.Pointer(&trustCount)),
	)
	if trustRet == NERR_Success && trustCount > 0 && trustBuf != 0 {
		sb.WriteString(fmt.Sprintf("Domain Trusts (%d):\n", trustCount))
		trusts := unsafe.Slice((*dsDomainTrusts)(unsafe.Pointer(trustBuf)), trustCount)
		for _, t := range trusts {
			netbios := ""
			dns := ""
			if t.NetbiosDomainName != nil {
				netbios = windows.UTF16PtrToString(t.NetbiosDomainName)
			}
			if t.DnsDomainName != nil {
				dns = windows.UTF16PtrToString(t.DnsDomainName)
			}

			flags := describeTrustFlags(t.Flags)
			if dns != "" {
				sb.WriteString(fmt.Sprintf("  %s (%s) — %s\n", netbios, dns, flags))
			} else {
				sb.WriteString(fmt.Sprintf("  %s — %s\n", netbios, flags))
			}
		}
		procNetApiBufferFree.Call(trustBuf)
	} else if trustRet != NERR_Success {
		sb.WriteString(fmt.Sprintf("Domain Trusts: (error %d)\n", trustRet))
	}

	result := sb.String()
	if result == "" {
		return structs.CommandResult{
			Output:    "Error: unable to retrieve domain information (machine may not be domain-joined)",
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func describeTrustFlags(flags uint32) string {
	var parts []string
	if flags&DS_DOMAIN_PRIMARY != 0 {
		parts = append(parts, "Primary")
	}
	if flags&DS_DOMAIN_TREE_ROOT != 0 {
		parts = append(parts, "TreeRoot")
	}
	if flags&DS_DOMAIN_IN_FOREST != 0 {
		parts = append(parts, "InForest")
	}
	if flags&DS_DOMAIN_DIRECT_OUTBOUND != 0 {
		parts = append(parts, "DirectOutbound")
	}
	if flags&DS_DOMAIN_DIRECT_INBOUND != 0 {
		parts = append(parts, "DirectInbound")
	}
	if flags&DS_DOMAIN_NATIVE_MODE != 0 {
		parts = append(parts, "NativeMode")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("flags=0x%x", flags)
	}
	return strings.Join(parts, ", ")
}
