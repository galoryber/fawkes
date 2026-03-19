//go:build !windows

package commands

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"
)

// bplistValue represents a value parsed from a binary plist.
type bplistValue struct {
	kind     byte // 'n'=nil, 'b'=bool, 'i'=int64, 'f'=float64, 's'=string, 'd'=data, 'a'=array, 'm'=dict
	boolVal  bool
	intVal   int64
	floatVal float64
	strVal   string
	dataVal  []byte
	arrayVal []bplistValue
	dictVal  map[string]bplistValue
}

// parseBplist parses an Apple binary property list (bplist00 format).
// Returns the root object as a bplistValue.
func parseBplist(data []byte) (bplistValue, error) {
	if len(data) < 40 { // 8 header + 32 trailer minimum
		return bplistValue{}, fmt.Errorf("bplist too short: %d bytes", len(data))
	}

	// Check magic
	if string(data[:6]) != "bplist" {
		return bplistValue{}, fmt.Errorf("not a binary plist (magic: %q)", string(data[:6]))
	}

	// Parse trailer (last 32 bytes)
	trailer := data[len(data)-32:]
	offsetSize := int(trailer[6])
	objectRefSize := int(trailer[7])
	numObjects := int(binary.BigEndian.Uint64(trailer[8:16]))
	topObject := int(binary.BigEndian.Uint64(trailer[16:24]))
	offsetTableOffset := int(binary.BigEndian.Uint64(trailer[24:32]))

	if offsetSize == 0 || objectRefSize == 0 || numObjects == 0 {
		return bplistValue{}, fmt.Errorf("invalid trailer: offsetSize=%d objectRefSize=%d numObjects=%d", offsetSize, objectRefSize, numObjects)
	}

	if offsetTableOffset+numObjects*offsetSize > len(data)-32 {
		return bplistValue{}, fmt.Errorf("offset table out of bounds")
	}

	// Read offset table
	offsets := make([]int, numObjects)
	for i := 0; i < numObjects; i++ {
		off := offsetTableOffset + i*offsetSize
		offsets[i] = readSizedInt(trailer[:0], data[off:off+offsetSize])
	}

	// Parse objects
	ctx := &bplistContext{
		data:          data,
		offsets:       offsets,
		objectRefSize: objectRefSize,
		numObjects:    numObjects,
	}

	return ctx.parseObject(topObject)
}

type bplistContext struct {
	data          []byte
	offsets       []int
	objectRefSize int
	numObjects    int
}

func (ctx *bplistContext) parseObject(index int) (bplistValue, error) {
	if index < 0 || index >= ctx.numObjects {
		return bplistValue{}, fmt.Errorf("object index %d out of range [0,%d)", index, ctx.numObjects)
	}

	offset := ctx.offsets[index]
	if offset >= len(ctx.data) {
		return bplistValue{}, fmt.Errorf("object %d offset %d out of bounds", index, offset)
	}

	marker := ctx.data[offset]
	objType := marker >> 4
	objInfo := int(marker & 0x0F)

	switch objType {
	case 0x0: // null/bool/fill
		switch marker {
		case 0x00:
			return bplistValue{kind: 'n'}, nil
		case 0x08:
			return bplistValue{kind: 'b', boolVal: false}, nil
		case 0x09:
			return bplistValue{kind: 'b', boolVal: true}, nil
		default:
			return bplistValue{kind: 'n'}, nil
		}

	case 0x1: // integer
		nbytes := 1 << objInfo
		start := offset + 1
		if start+nbytes > len(ctx.data) {
			return bplistValue{}, fmt.Errorf("integer truncated at %d", offset)
		}
		val := readBEInt(ctx.data[start : start+nbytes])
		return bplistValue{kind: 'i', intVal: val}, nil

	case 0x2: // real
		nbytes := 1 << objInfo
		start := offset + 1
		if start+nbytes > len(ctx.data) {
			return bplistValue{}, fmt.Errorf("real truncated at %d", offset)
		}
		if nbytes == 4 {
			bits := binary.BigEndian.Uint32(ctx.data[start : start+4])
			return bplistValue{kind: 'f', floatVal: float64(math.Float32frombits(bits))}, nil
		}
		if nbytes == 8 {
			bits := binary.BigEndian.Uint64(ctx.data[start : start+8])
			return bplistValue{kind: 'f', floatVal: math.Float64frombits(bits)}, nil
		}
		return bplistValue{}, fmt.Errorf("unsupported real size: %d", nbytes)

	case 0x4: // data
		size, dataStart, err := ctx.readSizeAndStart(offset, objInfo)
		if err != nil {
			return bplistValue{}, err
		}
		if dataStart+size > len(ctx.data) {
			return bplistValue{}, fmt.Errorf("data truncated at %d", offset)
		}
		buf := make([]byte, size)
		copy(buf, ctx.data[dataStart:dataStart+size])
		return bplistValue{kind: 'd', dataVal: buf}, nil

	case 0x5: // ASCII string
		size, dataStart, err := ctx.readSizeAndStart(offset, objInfo)
		if err != nil {
			return bplistValue{}, err
		}
		if dataStart+size > len(ctx.data) {
			return bplistValue{}, fmt.Errorf("string truncated at %d", offset)
		}
		return bplistValue{kind: 's', strVal: string(ctx.data[dataStart : dataStart+size])}, nil

	case 0x6: // Unicode string (UTF-16BE)
		count, dataStart, err := ctx.readSizeAndStart(offset, objInfo)
		if err != nil {
			return bplistValue{}, err
		}
		byteLen := count * 2
		if dataStart+byteLen > len(ctx.data) {
			return bplistValue{}, fmt.Errorf("unicode string truncated at %d", offset)
		}
		u16 := make([]uint16, count)
		for i := 0; i < count; i++ {
			u16[i] = binary.BigEndian.Uint16(ctx.data[dataStart+i*2 : dataStart+i*2+2])
		}
		return bplistValue{kind: 's', strVal: string(utf16.Decode(u16))}, nil

	case 0xA: // array
		count, refsStart, err := ctx.readSizeAndStart(offset, objInfo)
		if err != nil {
			return bplistValue{}, err
		}
		arr := make([]bplistValue, count)
		for i := 0; i < count; i++ {
			refOff := refsStart + i*ctx.objectRefSize
			if refOff+ctx.objectRefSize > len(ctx.data) {
				return bplistValue{}, fmt.Errorf("array ref truncated at %d", offset)
			}
			ref := readSizedInt(nil, ctx.data[refOff:refOff+ctx.objectRefSize])
			val, err := ctx.parseObject(ref)
			if err != nil {
				return bplistValue{}, fmt.Errorf("array[%d]: %w", i, err)
			}
			arr[i] = val
		}
		return bplistValue{kind: 'a', arrayVal: arr}, nil

	case 0xD: // dict
		count, refsStart, err := ctx.readSizeAndStart(offset, objInfo)
		if err != nil {
			return bplistValue{}, err
		}
		dict := make(map[string]bplistValue, count)
		keysStart := refsStart
		valsStart := refsStart + count*ctx.objectRefSize
		for i := 0; i < count; i++ {
			keyOff := keysStart + i*ctx.objectRefSize
			valOff := valsStart + i*ctx.objectRefSize
			if keyOff+ctx.objectRefSize > len(ctx.data) || valOff+ctx.objectRefSize > len(ctx.data) {
				return bplistValue{}, fmt.Errorf("dict ref truncated at %d", offset)
			}
			keyRef := readSizedInt(nil, ctx.data[keyOff:keyOff+ctx.objectRefSize])
			valRef := readSizedInt(nil, ctx.data[valOff:valOff+ctx.objectRefSize])

			keyVal, err := ctx.parseObject(keyRef)
			if err != nil {
				return bplistValue{}, fmt.Errorf("dict key[%d]: %w", i, err)
			}
			if keyVal.kind != 's' {
				continue // skip non-string keys
			}
			val, err := ctx.parseObject(valRef)
			if err != nil {
				return bplistValue{}, fmt.Errorf("dict[%q]: %w", keyVal.strVal, err)
			}
			dict[keyVal.strVal] = val
		}
		return bplistValue{kind: 'm', dictVal: dict}, nil

	default:
		// Skip unsupported types (date, UID, set)
		return bplistValue{kind: 'n'}, nil
	}
}

// readSizeAndStart reads the size field (handling the 0xF extended size) and
// returns the size and the offset where actual data begins.
func (ctx *bplistContext) readSizeAndStart(offset, objInfo int) (int, int, error) {
	if objInfo != 0x0F {
		return objInfo, offset + 1, nil
	}
	// Extended size: next byte is an integer marker
	if offset+2 > len(ctx.data) {
		return 0, 0, fmt.Errorf("extended size truncated at %d", offset)
	}
	sizeMarker := ctx.data[offset+1]
	if sizeMarker>>4 != 0x1 {
		return 0, 0, fmt.Errorf("expected integer marker for extended size, got 0x%02x", sizeMarker)
	}
	sizeBytes := 1 << (sizeMarker & 0x0F)
	start := offset + 2
	if start+sizeBytes > len(ctx.data) {
		return 0, 0, fmt.Errorf("extended size data truncated at %d", offset)
	}
	size := readSizedInt(nil, ctx.data[start:start+sizeBytes])
	return size, start + sizeBytes, nil
}

// readSizedInt reads a big-endian integer from a byte slice.
func readSizedInt(_ []byte, b []byte) int {
	val := 0
	for _, bb := range b {
		val = (val << 8) | int(bb)
	}
	return val
}

// readBEInt reads a big-endian signed integer from a byte slice.
func readBEInt(b []byte) int64 {
	switch len(b) {
	case 1:
		return int64(b[0])
	case 2:
		return int64(binary.BigEndian.Uint16(b))
	case 4:
		return int64(int32(binary.BigEndian.Uint32(b)))
	case 8:
		return int64(binary.BigEndian.Uint64(b))
	default:
		var val int64
		for _, bb := range b {
			val = (val << 8) | int64(bb)
		}
		return val
	}
}
