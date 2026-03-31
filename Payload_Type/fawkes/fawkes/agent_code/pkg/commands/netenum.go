//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
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

// netApiErrorDesc returns a human-readable description for common Win32/NetAPI error codes.
func netApiErrorDesc(code uintptr) string {
	switch code {
	case 5:
		return "ACCESS_DENIED"
	case 53:
		return "BAD_NETPATH (host unreachable)"
	case 1219:
		return "MULTIPLE_CONNECTIONS (session conflict)"
	case 1326:
		return "LOGON_FAILURE (bad credentials)"
	case 1355:
		return "NO_SUCH_DOMAIN"
	case 2114:
		return "SERVICE_NOT_STARTED"
	case 2221:
		return "USER_NOT_FOUND"
	case 2220:
		return "GROUP_NOT_FOUND"
	default:
		return ""
	}
}

// --- Type definitions ---

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

// domainInfoOutput is the JSON output for the domaininfo action.
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

const neAllActions = "users, localgroups, groupmembers, admins, domainusers, domaingroups, domaininfo, loggedon, sessions, shares, mapped"

// --- Execute dispatcher ---

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args netEnumArgs

	if task.Params == "" {
		return errorResult("Error: action parameter required.\nAvailable: " + neAllActions)
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
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
		return errorf("Unknown action: %s\nAvailable: %s", args.Action, neAllActions)
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
