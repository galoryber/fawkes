//go:build windows
// +build windows

package coff

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// BeaconDataParser helps BOFs parse their arguments
type BeaconDataParser struct {
	buffer []byte
	offset int
}

// beaconPrintf implements BeaconPrintf(int type, char* fmt, ...)
func (l *Loader) beaconPrintf(callbackType int, format uintptr) uintptr {
	// Read the format string from memory
	formatStr := readCString(format)
	
	// For simplicity, just capture the format string
	// A full implementation would parse varargs
	l.outputBuffer.WriteString(formatStr)
	l.outputBuffer.WriteString("\n")
	
	return 0
}

// beaconOutput implements BeaconOutput(int type, char* data, int len)
func (l *Loader) beaconOutput(callbackType int, data uintptr, length int) uintptr {
	if length > 0 && data != 0 {
		// Read data from memory
		dataBytes := make([]byte, length)
		for i := 0; i < length; i++ {
			dataBytes[i] = *(*byte)(unsafe.Pointer(data + uintptr(i)))
		}
		l.outputBuffer.Write(dataBytes)
	}
	return 0
}

// beaconDataParse implements BeaconDataParse(datap* parser, char* buffer, int size)
func (l *Loader) beaconDataParse(parser uintptr, buffer uintptr, size int) uintptr {
	if parser == 0 {
		return 0
	}

	// Initialize the parser structure
	// typedef struct {
	//   char * original;
	//   char * buffer;
	//   int    length;
	//   int    size;
	// } datap;
	
	*(*uintptr)(unsafe.Pointer(parser)) = buffer      // original
	*(*uintptr)(unsafe.Pointer(parser + 8)) = buffer  // buffer
	*(*int32)(unsafe.Pointer(parser + 16)) = int32(size) // length
	*(*int32)(unsafe.Pointer(parser + 20)) = int32(size) // size
	
	return 0
}

// beaconDataInt implements BeaconDataInt(datap* parser)
func (l *Loader) beaconDataInt(parser uintptr) int32 {
	if parser == 0 {
		return 0
	}

	// Read from parser->buffer
	buffer := *(*uintptr)(unsafe.Pointer(parser + 8))
	length := *(*int32)(unsafe.Pointer(parser + 16))
	
	if length < 8 {
		return 0
	}

	// Read 4-byte size prefix (should be 4 for an int)
	size := *(*uint32)(unsafe.Pointer(buffer))
	
	// Read 4-byte int value
	value := *(*int32)(unsafe.Pointer(buffer + 4))
	
	// Update parser
	*(*uintptr)(unsafe.Pointer(parser + 8)) = buffer + 8
	*(*int32)(unsafe.Pointer(parser + 16)) = length - 8
	
	_ = size // unused but follows format
	return value
}

// beaconDataShort implements BeaconDataShort(datap* parser)
func (l *Loader) beaconDataShort(parser uintptr) int16 {
	if parser == 0 {
		return 0
	}

	buffer := *(*uintptr)(unsafe.Pointer(parser + 8))
	length := *(*int32)(unsafe.Pointer(parser + 16))
	
	if length < 6 {
		return 0
	}

	// Read 4-byte size prefix (should be 2 for a short)
	size := *(*uint32)(unsafe.Pointer(buffer))
	
	// Read 2-byte short value
	value := *(*int16)(unsafe.Pointer(buffer + 4))
	
	// Update parser
	*(*uintptr)(unsafe.Pointer(parser + 8)) = buffer + 6
	*(*int32)(unsafe.Pointer(parser + 16)) = length - 6
	
	_ = size
	return value
}

// beaconDataExtract implements BeaconDataExtract(datap* parser, int* size)
func (l *Loader) beaconDataExtract(parser uintptr, outSize uintptr) uintptr {
	if parser == 0 {
		return 0
	}

	buffer := *(*uintptr)(unsafe.Pointer(parser + 8))
	length := *(*int32)(unsafe.Pointer(parser + 16))
	
	if length < 4 {
		if outSize != 0 {
			*(*int32)(unsafe.Pointer(outSize)) = 0
		}
		return 0
	}

	// Read 4-byte size
	size := *(*uint32)(unsafe.Pointer(buffer))
	dataPtr := buffer + 4
	
	// Update parser
	totalSize := 4 + int32(size)
	*(*uintptr)(unsafe.Pointer(parser + 8)) = buffer + uintptr(totalSize)
	*(*int32)(unsafe.Pointer(parser + 16)) = length - totalSize
	
	// Set output size if requested
	if outSize != 0 {
		*(*int32)(unsafe.Pointer(outSize)) = int32(size)
	}
	
	return dataPtr
}

// beaconFormatAlloc implements BeaconFormatAlloc(formatp* format, int maxsize)
func (l *Loader) beaconFormatAlloc(format uintptr, maxsize int) uintptr {
	// Allocate buffer for formatted output
	// For now, just return a dummy pointer
	return format
}

// beaconFormatPrintf implements BeaconFormatPrintf(formatp* format, char* fmt, ...)
func (l *Loader) beaconFormatPrintf(format uintptr, fmt uintptr) uintptr {
	// Simple implementation - just capture the format string
	formatStr := readCString(fmt)
	l.outputBuffer.WriteString(formatStr)
	return 0
}

// beaconFormatFree implements BeaconFormatFree(formatp* format)
func (l *Loader) beaconFormatFree(format uintptr) uintptr {
	// Nothing to free in our simple implementation
	return 0
}

// readCString reads a null-terminated string from memory
func readCString(addr uintptr) string {
	if addr == 0 {
		return ""
	}

	var result []byte
	for {
		b := *(*byte)(unsafe.Pointer(addr))
		if b == 0 {
			break
		}
		result = append(result, b)
		addr++
	}
	return string(result)
}

// PackArguments packs BOF arguments in the standard Beacon format
func PackArguments(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var buff []byte
	
	for _, arg := range args {
		if len(arg) < 2 {
			return nil, fmt.Errorf("invalid argument format: %s", arg)
		}

		argType := arg[0]
		argValue := arg[1:]

		switch argType {
		case 'z':
			// Null-terminated UTF-8 string
			data := []byte(argValue)
			data = append(data, 0) // Add null terminator
			
			// Pack: [4-byte size][string data with null]
			sizeBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
			buff = append(buff, sizeBuf...)
			buff = append(buff, data...)

		case 'Z':
			// Null-terminated UTF-16LE wide string
			wideData := encodeUTF16LE(argValue)
			wideData = append(wideData, 0, 0) // Add null terminator
			
			sizeBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(wideData)))
			buff = append(buff, sizeBuf...)
			buff = append(buff, wideData...)

		case 'i':
			// 32-bit integer
			var val uint32
			fmt.Sscanf(argValue, "%d", &val)
			
			sizeBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBuf, 4) // size = 4
			valBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(valBuf, val)
			
			buff = append(buff, sizeBuf...)
			buff = append(buff, valBuf...)

		case 's':
			// 16-bit short
			var val uint16
			fmt.Sscanf(argValue, "%d", &val)
			
			sizeBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBuf, 2) // size = 2
			valBuf := make([]byte, 2)
			binary.LittleEndian.PutUint16(valBuf, val)
			
			buff = append(buff, sizeBuf...)
			buff = append(buff, valBuf...)

		default:
			return nil, fmt.Errorf("unknown argument type: %c", argType)
		}
	}

	// Prefix with total size
	totalSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(totalSize, uint32(len(buff)))
	result := append(totalSize, buff...)
	
	return result, nil
}

// encodeUTF16LE encodes a string to UTF-16 Little Endian
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	result := make([]byte, 0, len(runes)*2)
	
	for _, r := range runes {
		if r <= 0xFFFF {
			// Basic Multilingual Plane
			result = append(result, byte(r), byte(r>>8))
		} else {
			// Surrogate pair for characters outside BMP
			r -= 0x10000
			high := uint16((r >> 10) + 0xD800)
			low := uint16((r & 0x3FF) + 0xDC00)
			result = append(result, byte(high), byte(high>>8), byte(low), byte(low>>8))
		}
	}
	
	return result
}
