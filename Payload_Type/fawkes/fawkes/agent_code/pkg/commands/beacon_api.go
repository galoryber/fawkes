//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DataParser matches the Cobalt Strike datap structure
type DataParser struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

var (
	bofKernel32         = syscall.MustLoadDLL("kernel32.dll")
	bofProcVirtualAlloc = bofKernel32.MustFindProc("VirtualAlloc")
)

const (
	bofMemCommit  = 0x1000
	bofMemReserve = 0x2000
)

// virtualAllocBytes allocates memory outside of Go's GC
func virtualAllocBytes(size uint32) (uintptr, error) {
	addr, _, err := bofProcVirtualAlloc.Call(0, uintptr(size), bofMemCommit|bofMemReserve, windows.PAGE_READWRITE)
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

// copyMemory copies bytes from src to dst
func copyMemory(dst, src uintptr, length uint32) {
	for i := uint32(0); i < length; i++ {
		*(*byte)(unsafe.Pointer(dst + uintptr(i))) = *(*byte)(unsafe.Pointer(src + uintptr(i)))
	}
}

// BeaconDataParse initializes the parser - matches Cobalt Strike API
func BeaconDataParse(datap *DataParser, buff uintptr, size uint32) uintptr {
	if size <= 0 {
		return 0
	}
	datap.original = buff
	datap.buffer = buff + uintptr(4) // Skip the 4-byte total size prefix
	datap.length = size - 4
	datap.size = size - 4
	return 1
}

// BeaconDataExtract extracts a length-prefixed binary blob - FIXED VERSION
// Allocates memory with VirtualAlloc to avoid Go GC issues
func BeaconDataExtract(datap *DataParser, size *uint32) uintptr {
	if datap.length <= 0 {
		return 0
	}

	// Read the 4-byte length prefix
	binaryLength := *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4

	if datap.length < binaryLength {
		return 0
	}

	// Allocate memory OUTSIDE of Go's heap using VirtualAlloc
	addr, err := virtualAllocBytes(binaryLength)
	if err != nil || addr == 0 {
		return 0
	}

	// Copy the data to the allocated memory
	copyMemory(addr, datap.buffer, binaryLength)

	// Update size if requested
	if size != nil && uintptr(unsafe.Pointer(size)) != 0 {
		*size = binaryLength
	}

	datap.buffer += uintptr(binaryLength)
	datap.length -= binaryLength

	return addr
}

// BeaconDataInt extracts a 4-byte integer
func BeaconDataInt(datap *DataParser) uintptr {
	if datap.length < 4 {
		return 0
	}
	value := *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4
	return uintptr(value)
}

// BeaconDataShort extracts a 2-byte integer
func BeaconDataShort(datap *DataParser) uintptr {
	if datap.length < 2 {
		return 0
	}
	value := *(*uint16)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(2)
	datap.length -= 2
	return uintptr(value)
}

// BeaconDataLength returns remaining data length
func BeaconDataLength(datap *DataParser) uintptr {
	return uintptr(datap.length)
}

// Output channel for BOF output
var bofOutputChannel chan string

// BeaconOutput captures BOF output
func BeaconOutput(outType int, data uintptr, length int) uintptr {
	if length <= 0 || bofOutputChannel == nil {
		return 0
	}
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = *(*byte)(unsafe.Pointer(data + uintptr(i)))
	}
	bofOutputChannel <- string(out)
	return 1
}

// BeaconPrintf handles formatted output from BOF
func BeaconPrintf(outType int, format uintptr, args ...uintptr) uintptr {
	if bofOutputChannel == nil {
		return 0
	}
	// Read the format string
	formatStr := readCString(format)
	// For now, just send the format string (full printf support would require more work)
	bofOutputChannel <- formatStr
	return 0
}

// readCString reads a null-terminated C string from memory
func readCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var result []byte
	for {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		result = append(result, b)
		ptr++
	}
	return string(result)
}

// PackArgs packs BOF arguments in Cobalt Strike format
// This matches the format expected by BeaconDataParse/BeaconDataExtract
func PackArgs(data []string) ([]byte, error) {
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
			// Binary data (hex encoded)
			packed, err := packBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("binary packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 'i':
			// 4-byte integer
			packed, err := packInt(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("int packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 's':
			// 2-byte short
			packed, err := packShort(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("short packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 'z':
			// Null-terminated ANSI string
			packed := packString(arg[1:])
			buff = append(buff, packed...)
		case 'Z':
			// Null-terminated wide string
			packed := packWideString(arg[1:])
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

func packBinary(data string) ([]byte, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(decoded)))
	buff = append(buff, decoded...)
	return buff, nil
}

func packInt(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(val))
	return buff, nil
}

func packShort(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(val))
	return buff, nil
}

func packString(s string) []byte {
	// ANSI string with null terminator
	data := append([]byte(s), 0)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}

func packWideString(s string) []byte {
	// UTF-16LE string with null terminator
	runes := []rune(s)
	// Each rune becomes 2 bytes, plus 2 bytes for null terminator
	data := make([]byte, 0, (len(runes)+1)*2)
	for _, r := range runes {
		data = append(data, byte(r), byte(r>>8))
	}
	// Add null terminator (2 bytes)
	data = append(data, 0, 0)

	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}
