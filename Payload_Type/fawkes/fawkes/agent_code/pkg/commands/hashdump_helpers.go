package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

// userHash holds a decoded SAM user record.
type userHash struct {
	username string
	rid      uint32
	lmHash   string
	ntHash   string
}

// Constants for SAM hash decryption
var (
	samQWERTY   = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	samDIGITS   = []byte("0123456789012345678901234567890123456789\x00")
	samNTPASSWD = []byte("NTPASSWORD\x00")
	samLMPASSWD = []byte("LMPASSWORD\x00")
	emptyLMHash = "aad3b435b51404eeaad3b435b51404ee"
	emptyNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

// Boot key permutation table
var bootKeyPerm = []int{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}

// deriveHashedBootKeyRC4 derives the hashed boot key from the SAM F value using RC4.
// SAM_KEY_DATA at offset 0x68: revision(4) + length(4) + salt(16) + key(16) + checksum(16)
func deriveHashedBootKeyRC4(fValue, bootKey []byte) ([]byte, byte, error) {
	if len(fValue) < 0x68+0x38 {
		return nil, 0, fmt.Errorf("F value too short for RC4 key data")
	}

	salt := fValue[0x70:0x80]        // offset 0x68 + 8 = 0x70
	encKey := fValue[0x80:0x90]      // offset 0x68 + 0x18 = 0x80
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

// deriveHashedBootKeyAES derives the hashed boot key from the SAM F value using AES.
// SAM_KEY_DATA_AES at offset 0x68: revision(4) + length(4) + checksumLen(4) + dataLen(4) + salt(16) + data(varies)
func deriveHashedBootKeyAES(fValue, bootKey []byte) ([]byte, byte, error) {
	if len(fValue) < 0x68+0x20 {
		return nil, 0, fmt.Errorf("F value too short for AES key data")
	}

	dataLen := binary.LittleEndian.Uint32(fValue[0x74:0x78]) // offset 0x68 + 0x0C
	salt := fValue[0x78:0x88]                                // offset 0x68 + 0x10
	encData := fValue[0x88 : 0x88+dataLen]                   // offset 0x68 + 0x20

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

// parseHexUint32 parses a hex string as a uint32.
func parseHexUint32(s string) (uint32, error) {
	var val uint32
	_, err := fmt.Sscanf(s, "%x", &val)
	return val, err
}

// parseUserVValue parses a SAM V value to extract username and decrypt NT/LM hashes.
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

// decryptSAMHash dispatches to the correct decryption method based on SAM revision.
func decryptSAMHash(hashData []byte, rid uint32, hashedBootKey, hashType []byte, samRevision byte) ([]byte, error) {
	if samRevision == 0x02 {
		return decryptSAMHashAES(hashData, rid, hashedBootKey)
	}
	return decryptSAMHashRC4(hashData, rid, hashedBootKey, hashType)
}

// decryptSAMHashRC4 decrypts a SAM hash using RC4.
// SAM_HASH: pekID(2) + revision(2) + hash(16)
func decryptSAMHashRC4(hashData []byte, rid uint32, hashedBootKey, hashType []byte) ([]byte, error) {
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

// decryptSAMHashAES decrypts a SAM hash using AES-128-CBC.
// SAM_HASH_AES: pekID(2) + revision(2) + dataOffset(4) + salt(16) + hash(32+)
func decryptSAMHashAES(hashData []byte, rid uint32, hashedBootKey []byte) ([]byte, error) {
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

// decryptDESHash applies the final DES decryption using the RID-derived keys.
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

// desKeysFromRID derives two DES keys from the RID.
func desKeysFromRID(rid uint32) ([]byte, []byte) {
	k := make([]byte, 4)
	binary.LittleEndian.PutUint32(k, rid)

	key1in := []byte{k[0], k[1], k[2], k[3], k[0], k[1], k[2]}
	key2in := []byte{k[3], k[0], k[1], k[2], k[3], k[0], k[1]}

	return expandDESKey(key1in), expandDESKey(key2in)
}

// expandDESKey expands a 7-byte key to an 8-byte DES key with parity.
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

// utf16LEToString converts a UTF-16LE byte slice to a Go string.
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
