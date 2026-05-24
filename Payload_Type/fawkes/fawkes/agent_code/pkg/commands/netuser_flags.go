//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

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
