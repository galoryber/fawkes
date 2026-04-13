//go:build windows
// +build windows

package commands

import (
	"strings"

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
	args, parseErr := unmarshalParams[netUserArgs](task)
	if parseErr != nil {
		return *parseErr
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
