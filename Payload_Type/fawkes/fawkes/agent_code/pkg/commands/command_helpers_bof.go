package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
)

// --- BOF Argument Packing helpers (from beacon_api.go) ---

// bofPackArgs packs BOF arguments in Cobalt Strike format.
// Each arg is a type-prefixed string: b=binary(hex), i=int32, s=short, z=ansi, Z=wide.
// Returns the packed bytes with a 4-byte total size prefix.
func bofPackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		if len(arg) < 1 {
			return nil, fmt.Errorf("empty argument")
		}
		switch arg[0] {
		case 'b':
			packed, err := bofPackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("binary packing error: %w", err)
			}
			buff = append(buff, packed...)
		case 'i':
			packed, err := bofPackInt(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("int packing error: %w", err)
			}
			buff = append(buff, packed...)
		case 's':
			packed, err := bofPackShort(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("short packing error: %w", err)
			}
			buff = append(buff, packed...)
		case 'z':
			packed := bofPackString(arg[1:])
			buff = append(buff, packed...)
		case 'Z':
			packed := bofPackWideString(arg[1:])
			buff = append(buff, packed...)
		default:
			return nil, fmt.Errorf("unknown type prefix '%c'", arg[0])
		}
	}

	// Prefix with total size
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(buff)))
	result = append(result, buff...)
	return result, nil
}

// bofPackBinary hex-decodes data and wraps with 4-byte length prefix
func bofPackBinary(data string) ([]byte, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(decoded)))
	buff = append(buff, decoded...)
	return buff, nil
}

// bofPackInt converts decimal string to 4-byte little-endian integer
func bofPackInt(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(val))
	return buff, nil
}

// bofPackShort converts decimal string to 2-byte little-endian integer
func bofPackShort(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(val))
	return buff, nil
}

// bofPackString wraps ANSI string with null terminator and 4-byte length prefix
func bofPackString(s string) []byte {
	data := append([]byte(s), 0)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}

// bofPackWideString encodes UTF-16LE string with null terminator and 4-byte length prefix
func bofPackWideString(s string) []byte {
	runes := []rune(s)
	data := make([]byte, 0, (len(runes)+1)*2)
	for _, r := range runes {
		data = append(data, byte(r), byte(r>>8))
	}
	data = append(data, 0, 0)

	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}
