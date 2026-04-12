//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

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
