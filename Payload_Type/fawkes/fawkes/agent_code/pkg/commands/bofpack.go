//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf16"
)

// BOFPack packs BOF arguments in Cobalt Strike format
// This is a fixed version of go-coff's BOFPack that properly encodes UTF-16 strings
func BOFPack(data []string) ([]byte, error) {
	// If there are no arguments, return nil
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		if len(arg) < 2 {
			return nil, fmt.Errorf("[BOFPack] the argument '%s' is not valid", arg)
		}
		switch arg[0] {
		case 'b':
			// b - binary data
			data, err := BOFPackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the binary data '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'i':
			// i - 4-byte integer
			data, err := BOFPackIntString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the integer '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 's':
			// s - 2-byte short integer
			data, err := BOFPackShortString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the short integer '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'z':
			// z - zero-terminated+encoded string
			data, err := BOFPackString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the string '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'Z':
			// Z - zero-terminated wide-char string
			data, err := BOFPackWideString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("[BOFPack] there was an error packing the wide string '%s': %s", arg[1:], err)
			}
			buff = append(buff, data...)
		default:
			return nil, fmt.Errorf("[BOFPack] the data type prefix '%s' in '%s' is not valid, try 'b', 'i', 's', 'z', or 'Z'", string(arg[0]), arg)
		}
	}
	// Prefix the buffer with its size
	rData := make([]byte, 4)
	binary.LittleEndian.PutUint32(rData, uint32(len(buff)))
	// Append the buffer
	rData = append(rData, buff...)
	return rData, nil
}

// BOFPackBinary hex decodes the string and packs binary data
func BOFPackBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackBinary] there was an error hex decoding the string '%s': %s", data, err)
	}
	return hexData, nil
}

// BOFPackInt packs a 4-byte unsigned integer
func BOFPackInt(i uint32) ([]byte, error) {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(i))
	return buff, nil
}

// BOFPackIntString converts the string to an unsigned 4-byte integer and packs it
func BOFPackIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackIntString] there was an error converting the string '%s' to an integer: %s", s, err)
	}
	return BOFPackInt(uint32(i))
}

// BOFPackShort packs a 2-byte unsigned integer
func BOFPackShort(i uint16) ([]byte, error) {
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(i))
	return buff, nil
}

// BOFPackShortString converts the string to an unsigned 2-byte integer and packs it
func BOFPackShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("[BOFPackShortString] there was an error converting the string '%s' to an integer: %s", s, err)
	}
	return BOFPackShort(uint16(i))
}

// BOFPackString converts the string to a zero-terminated UTF-8 string
// 'z' type = null-terminated UTF-8 (plain ASCII/UTF-8 bytes)
func BOFPackString(s string) ([]byte, error) {
	// Convert to UTF-8 bytes (strings in Go are already UTF-8)
	data := []byte(s)
	// Add null terminator
	data = append(data, 0)
	
	buff := make([]byte, 4)
	// Prefix the data size in bytes
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	
	// Append the UTF-8 string data
	buff = append(buff, data...)
	return buff, nil
}

// BOFPackWideString converts the string to a zero-terminated wide-char string
// FIXED: Properly encodes UTF-16LE with both bytes of each character
func BOFPackWideString(s string) ([]byte, error) {
	// Convert to UTF-16
	d := utf16.Encode([]rune(s))
	// Add null terminator
	d = append(d, 0)
	
	buff := make([]byte, 4)
	// Prefix the data size in bytes (each UTF-16 code unit is 2 bytes)
	binary.LittleEndian.PutUint32(buff, uint32(len(d)*2))
	
	// Pack each UTF-16 code unit as little-endian (low byte, then high byte)
	for _, c := range d {
		buff = append(buff, byte(c), byte(c>>8))
	}
	return buff, nil
}
