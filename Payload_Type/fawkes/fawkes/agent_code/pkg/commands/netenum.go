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
	return "Unified Windows network enumeration — users, groups, shares, sessions, logons, domain info"
}

type netEnumArgs struct {
	Action string `json:"action"`
	Target string `json:"target"` // remote host for loggedon/sessions/shares/localgroups/admins; group name for groupmembers
	Group  string `json:"group"`  // group name for groupmembers/admins (overrides target for group name)
}

var (
	netapi32NE              = windows.NewLazySystemDLL("netapi32.dll")
	mprNE                   = windows.NewLazySystemDLL("mpr.dll")
	procNetUserEnum         = netapi32NE.NewProc("NetUserEnum")
	procNetLocalGroupEnum   = netapi32NE.NewProc("NetLocalGroupEnum")
	procNetLocalGroupGetMem = netapi32NE.NewProc("NetLocalGroupGetMembers")
	procNetGroupEnum        = netapi32NE.NewProc("NetGroupEnum")
	procNetApiBufferFree    = netapi32NE.NewProc("NetApiBufferFree")
	procDsGetDcNameW        = netapi32NE.NewProc("DsGetDcNameW")
	procNetUserModalsGet    = netapi32NE.NewProc("NetUserModalsGet")
	procDsEnumDomainTrusts  = netapi32NE.NewProc("DsEnumerateDomainTrustsW")
	procNetWkstaUserEnum    = netapi32NE.NewProc("NetWkstaUserEnum")
	procNetSessionEnum      = netapi32NE.NewProc("NetSessionEnum")
	procNetShareEnum        = netapi32NE.NewProc("NetShareEnum")
	procWNetOpenEnum        = mprNE.NewProc("WNetOpenEnumW")
	procWNetEnumRes         = mprNE.NewProc("WNetEnumResourceW")
	procWNetCloseEnum       = mprNE.NewProc("WNetCloseEnum")
)

const (
	NERR_Success       = 0
	ERROR_MORE_DATA    = 234
	MAX_PREFERRED_LEN  = 0xFFFFFFFF
	FILTER_NORMAL_ACCT = 0x0002

	// DS_DOMAIN_TRUSTS flags
	DS_DOMAIN_IN_FOREST       = 0x0001
	DS_DOMAIN_DIRECT_OUTBOUND = 0x0002
	DS_DOMAIN_TREE_ROOT       = 0x0004
	DS_DOMAIN_PRIMARY         = 0x0008
	DS_DOMAIN_NATIVE_MODE     = 0x0010
	DS_DOMAIN_DIRECT_INBOUND  = 0x0020

	// Share types
	STYPE_DISKTREE  = 0x00000000
	STYPE_PRINTQ    = 0x00000001
	STYPE_DEVICE    = 0x00000002
	STYPE_IPC       = 0x00000003
	STYPE_SPECIAL   = 0x80000000
	STYPE_TEMPORARY = 0x40000000
	STYPE_MASK      = 0x000000FF

	// WNet resource types
	RESOURCETYPE_DISK  = 0x00000001
	RESOURCE_CONNECTED = 0x00000001
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

// localGroupMembersInfo2 provides SID usage type (user vs group vs well-known)
type localGroupMembersInfo2 struct {
	SID           uintptr
	SIDUsage      uint32
	DomainAndName *uint16
}

// GROUP_INFO_0 - just the group name
type groupInfo0 struct {
	Name *uint16
}

// DOMAIN_CONTROLLER_INFO
type domainControllerInfo struct {
	DomainControllerName     *uint16
	DomainControllerAddress  *uint16
	DomainControllerAddrType uint32
	DomainGuid               [16]byte
	DomainName               *uint16
	DnsForestName            *uint16
	Flags                    uint32
	DcSiteName               *uint16
	ClientSiteName           *uint16
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

// WKSTA_USER_INFO_1 - logged-on user info
type wkstaUserInfo1 struct {
	Username     uintptr // LPWSTR
	LogonDomain  uintptr // LPWSTR
	OtherDomains uintptr // LPWSTR
	LogonServer  uintptr // LPWSTR
}

// SESSION_INFO_10 (no admin required)
type sessionInfo10 struct {
	ClientName uintptr // LPWSTR
	UserName   uintptr // LPWSTR
	Time       uint32
	IdleTime   uint32
}

// SESSION_INFO_502 (requires admin, has transport info)
type sessionInfo502 struct {
	ClientName uintptr // LPWSTR
	UserName   uintptr // LPWSTR
	NumOpens   uint32
	Time       uint32
	IdleTime   uint32
	UserFlags  uint32
	ClientType uintptr // LPWSTR
}

// SHARE_INFO_2 (local shares with path)
type shareInfo2 struct {
	Name        *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
}

// SHARE_INFO_1 (remote shares, no path)
type shareInfo1 struct {
	Name   *uint16
	Type   uint32
	Remark *uint16
}

// NETRESOURCE for WNet mapped drive enumeration
type netResource struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

// netEnumEntry is the JSON output for most net-enum actions.
type netEnumEntry struct {
	Name      string `json:"name"`
	Comment   string `json:"comment,omitempty"`
	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Flags     string `json:"flags,omitempty"`
	DNS       string `json:"dns,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Server    string `json:"server,omitempty"`
	Path      string `json:"path,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Client    string `json:"client,omitempty"`
	Time      string `json:"time,omitempty"`
	Idle      string `json:"idle,omitempty"`
	Opens     int    `json:"opens,omitempty"`
	Transport string `json:"transport,omitempty"`
}

const neAllActions = "users, localgroups, groupmembers, admins, domainusers, domaingroups, domaininfo, loggedon, sessions, shares, mapped"

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args netEnumArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: action parameter required.\nAvailable: " + neAllActions,
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
		return netEnumLocalGroups(args.Target)
	case "groupmembers":
		group := args.Group
		if group == "" {
			group = args.Target // backward compatibility
		}
		return netEnumGroupMembers(group, args.Target)
	case "admins":
		return netEnumGroupMembers("Administrators", args.Target)
	case "domainusers":
		return netEnumDomainUsers()
	case "domaingroups":
		return netEnumDomainGroups()
	case "domaininfo":
		return netEnumDomainInfo()
	case "loggedon":
		return netEnumLoggedOn(args.Target)
	case "sessions":
		return netEnumSessions(args.Target)
	case "shares":
		if args.Target != "" {
			return netEnumRemoteShares(args.Target)
		}
		return netEnumLocalShares()
	case "mapped":
		return netEnumMappedDrives()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: %s", args.Action, neAllActions),
			Status:    "error",
			Completed: true,
		}
	}
}

// --- Helpers ---

// neWideToString converts a Windows LPWSTR (uintptr) to a Go string.
func neWideToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	for i := uintptr(0); ; i += 2 {
		ch := *(*uint16)(unsafe.Pointer(ptr + i))
		if ch == 0 {
			break
		}
		chars = append(chars, ch)
		if i > 1024 {
			break
		}
	}
	return windows.UTF16ToString(chars)
}

// neFormatDuration converts seconds to a human-readable duration string.
func neFormatDuration(seconds uint32) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
}

// neGetServerPtr returns a UTF-16 pointer for the server name (with UNC prefix), or nil for local.
func neGetServerPtr(server string) (*uint16, error) {
	if server == "" {
		return nil, nil
	}
	if !strings.HasPrefix(server, "\\\\") {
		server = "\\\\" + server
	}
	return windows.UTF16PtrFromString(server)
}

// neDescribeShareType converts a share type bitmask to a human-readable string.
func neDescribeShareType(stype uint32) string {
	baseType := stype & STYPE_MASK
	special := stype&STYPE_SPECIAL != 0

	var typeName string
	switch baseType {
	case STYPE_DISKTREE:
		typeName = "Disk"
	case STYPE_PRINTQ:
		typeName = "Print"
	case STYPE_DEVICE:
		typeName = "Device"
	case STYPE_IPC:
		typeName = "IPC"
	default:
		typeName = fmt.Sprintf("0x%x", baseType)
	}

	if special {
		typeName += " (Admin)"
	}
	if stype&STYPE_TEMPORARY != 0 {
		typeName += " (Temp)"
	}

	return typeName
}

// getDomainControllerName returns the DC name for domain-level queries.
func getDomainControllerName() (string, error) {
	var dcInfo *domainControllerInfo
	ret, _, _ := procDsGetDcNameW.Call(
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&dcInfo)),
	)
	if ret != NERR_Success {
		return "", fmt.Errorf("DsGetDcNameW failed with error %d (machine may not be domain-joined)", ret)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(dcInfo)))

	dcName := windows.UTF16PtrToString(dcInfo.DomainControllerName)
	dcName = strings.TrimPrefix(dcName, "\\\\")
	return dcName, nil
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

	var entries []netEnumEntry
	for _, u := range users {
		entries = append(entries, netEnumEntry{Name: u, Type: "local_user"})
	}
	if len(entries) == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	data, _ := json.Marshal(entries)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: localgroups (enhanced with remote server support) ---

func netEnumLocalGroups(target string) structs.CommandResult {
	serverPtr, err := neGetServerPtr(target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
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

	var entries []netEnumEntry
	for _, g := range groups {
		entries = append(entries, netEnumEntry{Name: g.name, Comment: g.comment, Type: "local_group", Server: target})
	}
	if len(entries) == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	data, _ := json.Marshal(entries)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: groupmembers (enhanced with remote server + SID type) ---

func netEnumGroupMembers(group, target string) structs.CommandResult {
	if group == "" {
		return structs.CommandResult{
			Output:    "Error: group name is required for groupmembers/admins action. Use -group <name> or -target <name>.",
			Status:    "error",
			Completed: true,
		}
	}

	// For groupmembers, target is the group name (backward compat) unless group param is set.
	// When group is explicitly set, target becomes the remote server.
	server := ""
	if group != target && target != "" {
		server = target
	}

	serverPtr, err := neGetServerPtr(server)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("NetLocalGroupGetMembers failed with error %d (group: %s)", ret, group),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: domainusers ---

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
			0,
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

	var entries []netEnumEntry
	for _, u := range users {
		entries = append(entries, netEnumEntry{Name: u, Type: "domain_user", Source: dcName})
	}
	if len(entries) == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	data, _ := json.Marshal(entries)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: domaingroups ---

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
			0,
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

	var entries []netEnumEntry
	for _, g := range groups {
		entries = append(entries, netEnumEntry{Name: g, Type: "domain_group", Source: dcName})
	}
	if len(entries) == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	data, _ := json.Marshal(entries)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: domaininfo ---

type domainInfoOutput struct {
	DCName      string         `json:"dc_name,omitempty"`
	DCAddress   string         `json:"dc_address,omitempty"`
	Domain      string         `json:"domain,omitempty"`
	Forest      string         `json:"forest,omitempty"`
	DCSite      string         `json:"dc_site,omitempty"`
	ClientSite  string         `json:"client_site,omitempty"`
	MinPassLen  uint32         `json:"min_password_length,omitempty"`
	MaxPassAge  uint32         `json:"max_password_age_days,omitempty"`
	MinPassAge  uint32         `json:"min_password_age_days,omitempty"`
	PassHistLen uint32         `json:"password_history_length,omitempty"`
	ForceLogoff string         `json:"force_logoff,omitempty"`
	Trusts      []netEnumEntry `json:"trusts,omitempty"`
}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: DsGetDcNameW failed (error %d — machine may not be domain-joined)", ret),
			Status:    "error",
			Completed: true,
		}
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
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: loggedon ---

func netEnumLoggedOn(target string) structs.CommandResult {
	var serverPtr uintptr
	if target != "" {
		serverName, err := windows.UTF16PtrFromString(`\\` + target)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		serverPtr = uintptr(unsafe.Pointer(serverName))
	}

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetWkstaUserEnum.Call(
		serverPtr,
		1,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("NetWkstaUserEnum failed: error %d", ret),
			Status:    "error",
			Completed: true,
		}
	}

	if entriesRead == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(wkstaUserInfo1{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*wkstaUserInfo1)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Name:   neWideToString(entry.Username),
			Domain: neWideToString(entry.LogonDomain),
			Server: neWideToString(entry.LogonServer),
			Type:   "loggedon",
		})
	}

	data, _ := json.Marshal(entries)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: sessions ---

func netEnumSessions(target string) structs.CommandResult {
	// Try level 502 first (more detail, requires admin)
	output, err := neEnumSessions502(target)
	if err != nil {
		// Fall back to level 10 (less detail, no admin required)
		output, err = neEnumSessions10(target)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating sessions: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	return structs.CommandResult{Output: output, Status: "success", Completed: true}
}

func neEnumSessions502(target string) (string, error) {
	var serverPtr uintptr
	if target != "" {
		serverName, err := windows.UTF16PtrFromString(`\\` + target)
		if err != nil {
			return "", err
		}
		serverPtr = uintptr(unsafe.Pointer(serverName))
	}

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetSessionEnum.Call(
		serverPtr, 0, 0, 502,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}
	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 502 failed: error %d", ret)
	}
	if entriesRead == 0 {
		return "[]", nil
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(sessionInfo502{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo502)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Client:    neWideToString(entry.ClientName),
			Name:      neWideToString(entry.UserName),
			Opens:     int(entry.NumOpens),
			Time:      neFormatDuration(entry.Time),
			Idle:      neFormatDuration(entry.IdleTime),
			Transport: neWideToString(entry.ClientType),
			Type:      "session",
		})
	}

	data, _ := json.Marshal(entries)
	return string(data), nil
}

func neEnumSessions10(target string) (string, error) {
	var serverPtr uintptr
	if target != "" {
		serverName, err := windows.UTF16PtrFromString(`\\` + target)
		if err != nil {
			return "", err
		}
		serverPtr = uintptr(unsafe.Pointer(serverName))
	}

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetSessionEnum.Call(
		serverPtr, 0, 0, 10,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}
	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 10 failed: error %d", ret)
	}
	if entriesRead == 0 {
		return "[]", nil
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(sessionInfo10{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo10)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Client: neWideToString(entry.ClientName),
			Name:   neWideToString(entry.UserName),
			Time:   neFormatDuration(entry.Time),
			Idle:   neFormatDuration(entry.IdleTime),
			Type:   "session",
		})
	}

	data, _ := json.Marshal(entries)
	return string(data), nil
}

// --- Action: shares (local) ---

func netEnumLocalShares() structs.CommandResult {
	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		0, 2,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating local shares: NetShareEnum returned %d", ret),
			Status:    "error",
			Completed: true,
		}
	}

	if buf == 0 || entriesRead == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	defer procNetApiBufferFree.Call(buf)

	entries := unsafe.Slice((*shareInfo2)(unsafe.Pointer(buf)), entriesRead)
	var out []netEnumEntry

	for _, entry := range entries {
		e := netEnumEntry{Type: "share"}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Path != nil {
			e.Path = windows.UTF16PtrToString(entry.Path)
		}
		if entry.Remark != nil {
			e.Comment = windows.UTF16PtrToString(entry.Remark)
		}
		e.Source = neDescribeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: shares (remote, when target is specified) ---

func netEnumRemoteShares(target string) structs.CommandResult {
	serverName := target
	if !strings.HasPrefix(serverName, "\\\\") {
		serverName = "\\\\" + serverName
	}

	serverPtr, _ := syscall.UTF16PtrFromString(serverName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating shares on %s: NetShareEnum returned %d", target, ret),
			Status:    "error",
			Completed: true,
		}
	}

	if buf == 0 || entriesRead == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}
	defer procNetApiBufferFree.Call(buf)

	entries := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), entriesRead)
	var out []netEnumEntry

	for _, entry := range entries {
		e := netEnumEntry{Type: "share", Server: target}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Remark != nil {
			e.Comment = windows.UTF16PtrToString(entry.Remark)
		}
		e.Source = neDescribeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}

// --- Action: mapped ---

func netEnumMappedDrives() structs.CommandResult {
	var handle syscall.Handle

	ret, _, _ := procWNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_DISK),
		0, 0,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != NERR_Success {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening network drive enumeration: WNetOpenEnum returned %d", ret),
			Status:    "error",
			Completed: true,
		}
	}
	defer procWNetCloseEnum.Call(uintptr(handle))

	var out []netEnumEntry
	bufSize := uint32(16384)
	buf := make([]byte, bufSize)

	for {
		entries := uint32(0xFFFFFFFF)
		currentBufSize := bufSize
		enumRet, _, _ := procWNetEnumRes.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&currentBufSize)),
		)

		if enumRet != NERR_Success && enumRet != ERROR_MORE_DATA {
			break
		}

		ptr := unsafe.Pointer(&buf[0])
		resSize := unsafe.Sizeof(netResource{})
		for i := uint32(0); i < entries; i++ {
			res := (*netResource)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*resSize))
			e := netEnumEntry{Type: "mapped"}
			if res.LocalName != nil {
				e.Name = windows.UTF16PtrToString(res.LocalName)
			}
			if res.RemoteName != nil {
				e.Path = windows.UTF16PtrToString(res.RemoteName)
			}
			if res.Provider != nil {
				e.Provider = windows.UTF16PtrToString(res.Provider)
			}
			out = append(out, e)
		}

		if enumRet != ERROR_MORE_DATA {
			break
		}
	}

	if len(out) == 0 {
		return structs.CommandResult{Output: "[]", Status: "success", Completed: true}
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{Output: string(data), Status: "success", Completed: true}
}
