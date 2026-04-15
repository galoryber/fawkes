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
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// USER_INFO_1003 for setting password
type userInfo1003 struct {
	Password *uint16
}

// USER_INFO_4 for detailed info (level 4)
type userInfo4 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Params          *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      uintptr
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserSid         uintptr
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// LOCALGROUP_MEMBERS_INFO_3 for add/remove member
type lgMemberInfo3 struct {
	DomainAndName *uint16
}

func (c *NetUserCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: add, delete, info, password, group-add, group-remove, disable, enable, lockout")
	}

	var args netUserArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer structs.ZeroString(&args.Password)

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
	case "disable":
		return netUserDisable(args)
	case "enable":
		return netUserEnable(args)
	case "lockout":
		return netUserLockout(args)
	default:
		return errorf("Unknown action: %s\nAvailable: add, delete, info, password, group-add, group-remove, disable, enable, lockout", args.Action)
	}
}

func netUserAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for add action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for add action")
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
		return errorf("Error creating user '%s': NetUserAdd returned %d %s (parm_err=%d)", args.Username, ret, netApiErrorDesc(ret), parmErr)
	}

	return successf("Successfully created user '%s'", args.Username)
}

func netUserDelete(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for delete action")
	}

	namePtr, _ := syscall.UTF16PtrFromString(args.Username)

	ret, _, _ := procNetUserDel.Call(
		0, // local server
		uintptr(unsafe.Pointer(namePtr)),
	)

	if ret != 0 {
		return errorf("Error deleting user '%s': NetUserDel returned %d %s", args.Username, ret, netApiErrorDesc(ret))
	}

	return successf("Successfully deleted user '%s'", args.Username)
}

func netUserInfo(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for info action")
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
		return errorf("Error getting info for '%s': NetUserGetInfo returned %d %s", args.Username, ret, netApiErrorDesc(ret))
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

	return successResult(sb.String())
}

func netUserPassword(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for password action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for password action")
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
		return errorf("Error setting password for '%s': NetUserSetInfo returned %d %s", args.Username, ret, netApiErrorDesc(ret))
	}

	return successf("Successfully changed password for '%s'", args.Username)
}

func netUserGroupAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-add action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-add action")
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
		return errorf("Error adding '%s' to group '%s': NetLocalGroupAddMembers returned %d %s", args.Username, args.Group, ret, netApiErrorDesc(ret))
	}

	return successf("Successfully added '%s' to local group '%s'", args.Username, args.Group)
}

func netUserGroupRemove(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-remove action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-remove action")
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
		return errorf("Error removing '%s' from group '%s': NetLocalGroupDelMembers returned %d %s", args.Username, args.Group, ret, netApiErrorDesc(ret))
	}

	return successf("Successfully removed '%s' from local group '%s'", args.Username, args.Group)
}

// userInfo1008 is USER_INFO_1008 — used with level 1008 to set/clear account flags.
type userInfo1008 struct {
	Flags uint32
}

// netUserGetFlags retrieves the current UF_ flags for a user account.
func netUserGetFlags(username string) (uint32, error) {
	namePtr, _ := syscall.UTF16PtrFromString(username)
	var buf uintptr
	ret, _, _ := procNetUserGetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), 4, uintptr(unsafe.Pointer(&buf)))
	if ret != 0 {
		return 0, fmt.Errorf("NetUserGetInfo returned %d %s", ret, netApiErrorDesc(ret))
	}
	defer procNetApiBufferFreeNU.Call(buf)
	info := (*userInfo4)(unsafe.Pointer(buf))
	return info.Flags, nil
}

// netUserSetFlags sets the UF_ flags for a user account via NetUserSetInfo level 1008.
func netUserSetFlags(username string, flags uint32) error {
	namePtr, _ := syscall.UTF16PtrFromString(username)
	info := userInfo1008{Flags: flags}
	ret, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), USER_UF_INFO, uintptr(unsafe.Pointer(&info)), 0)
	if ret != 0 {
		return fmt.Errorf("NetUserSetInfo returned %d %s", ret, netApiErrorDesc(ret))
	}
	return nil
}

// netUserDisable disables a user account by setting UF_ACCOUNTDISABLE (T1531).
func netUserDisable(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for disable action")
	}

	flags, err := netUserGetFlags(args.Username)
	if err != nil {
		return errorf("Error getting flags for '%s': %v", args.Username, err)
	}

	if flags&UF_ACCOUNTDISABLE != 0 {
		return successf("Account '%s' is already disabled", args.Username)
	}

	flags |= UF_ACCOUNTDISABLE
	if err := netUserSetFlags(args.Username, flags); err != nil {
		return errorf("Error disabling '%s': %v", args.Username, err)
	}

	return successf("Successfully disabled account '%s'", args.Username)
}

// netUserEnable re-enables a disabled user account by clearing UF_ACCOUNTDISABLE.
func netUserEnable(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for enable action")
	}

	flags, err := netUserGetFlags(args.Username)
	if err != nil {
		return errorf("Error getting flags for '%s': %v", args.Username, err)
	}

	if flags&UF_ACCOUNTDISABLE == 0 {
		return successf("Account '%s' is already enabled", args.Username)
	}

	flags &^= UF_ACCOUNTDISABLE
	if err := netUserSetFlags(args.Username, flags); err != nil {
		return errorf("Error enabling '%s': %v", args.Username, err)
	}

	return successf("Successfully enabled account '%s'", args.Username)
}

// netUserLockout locks out a user account by setting UF_LOCKOUT (T1531).
// Note: Account lockout is typically managed by domain policy and resets automatically.
// This forces the lockout flag — the account cannot authenticate until unlocked.
func netUserLockout(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for lockout action")
	}

	flags, err := netUserGetFlags(args.Username)
	if err != nil {
		return errorf("Error getting flags for '%s': %v", args.Username, err)
	}

	if flags&UF_LOCKOUT != 0 {
		return successf("Account '%s' is already locked out", args.Username)
	}

	flags |= UF_LOCKOUT
	if err := netUserSetFlags(args.Username, flags); err != nil {
		return errorf("Error locking out '%s': %v", args.Username, err)
	}

	return successf("Successfully locked out account '%s'", args.Username)
}
