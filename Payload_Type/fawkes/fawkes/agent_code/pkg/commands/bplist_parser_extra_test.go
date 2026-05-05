//go:build !windows

package commands

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestParseBplistInvalidTrailer covers the trailer validation error paths (lines 44, 48).
func TestParseBplistInvalidTrailer(t *testing.T) {
	t.Run("offsetSize zero", func(t *testing.T) {
		data := buildBplist([][]byte{bplistNull()}, 0)
		data[len(data)-32+6] = 0 // zero out offsetSize field
		_, err := parseBplist(data)
		if err == nil {
			t.Error("expected error for offsetSize=0")
		}
	})

	t.Run("objectRefSize zero", func(t *testing.T) {
		data := buildBplist([][]byte{bplistNull()}, 0)
		data[len(data)-32+7] = 0 // zero out objectRefSize field
		_, err := parseBplist(data)
		if err == nil {
			t.Error("expected error for objectRefSize=0")
		}
	})

	t.Run("numObjects zero", func(t *testing.T) {
		data := buildBplist([][]byte{bplistNull()}, 0)
		binary.BigEndian.PutUint64(data[len(data)-32+8:], 0) // zero numObjects
		_, err := parseBplist(data)
		if err == nil {
			t.Error("expected error for numObjects=0")
		}
	})

	t.Run("offset table out of bounds", func(t *testing.T) {
		data := buildBplist([][]byte{bplistNull()}, 0)
		// Push offsetTableOffset past the usable area so the bounds check fails
		binary.BigEndian.PutUint64(data[len(data)-32+24:], uint64(len(data)))
		_, err := parseBplist(data)
		if err == nil {
			t.Error("expected error for offset table out of bounds")
		}
	})
}

// TestParseObjectEdgeCases calls parseObject directly to reach uncovered error branches.
// Tests are in the same package so bplistContext is accessible.
func TestParseObjectEdgeCases(t *testing.T) {
	t.Run("object offset beyond data (line 83)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x00, 0x01, 0x02},
			offsets:       []int{99}, // 99 >= len(data)=3
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for offset beyond data")
		}
	})

	// Integer (0x1x): marker 0x11 means 1<<1=2 content bytes; only 1 present.
	t.Run("integer truncated (line 107)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x11, 0xAB}, // needs 2 content bytes, only 1 present
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated integer")
		}
	})

	// Real (0x2x): marker 0x22 means 1<<2=4 content bytes; only 2 present.
	t.Run("real truncated (line 116)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x22, 0x01, 0x02}, // needs 4 content bytes
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated real")
		}
	})

	// Real (0x2x): marker 0x22 means 4-byte (float32) path (lines 119-122).
	t.Run("4-byte float (lines 119-122)", func(t *testing.T) {
		f32bits := math.Float32bits(float32(math.Pi))
		b := []byte{0x22, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], f32bits)
		ctx := &bplistContext{
			data:          b,
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		val, err := ctx.parseObject(0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val.kind != 'f' {
			t.Errorf("expected kind='f', got '%c'", val.kind)
		}
		if math.Abs(val.floatVal-math.Pi) > 0.001 {
			t.Errorf("float value = %f, want ~%f", val.floatVal, math.Pi)
		}
	})

	// Data (0x4x): 0x4F triggers extended size; only 1 byte present so readSizeAndStart fails.
	t.Run("data readSizeAndStart error (line 131)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x4F},
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for data readSizeAndStart failure")
		}
	})

	// Data (0x4x): 0x43 claims 3 bytes but only 2 content bytes present.
	t.Run("data content truncated (line 134)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x43, 0xAA, 0xBB}, // claims 3 content bytes, only 2 available
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated data content")
		}
	})

	// ASCII string (0x5x): 0x5F triggers extended size; only 1 byte present.
	t.Run("string readSizeAndStart error (line 143)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x5F},
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for string readSizeAndStart failure")
		}
	})

	// ASCII string (0x5x): 0x53 claims 3 chars but only 2 present.
	t.Run("string content truncated (line 146)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x53, 'A', 'B'}, // claims 3 chars, only 2 present
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated string content")
		}
	})

	// Unicode string (0x6x): 0x6F triggers extended size; only 1 byte present.
	t.Run("unicode readSizeAndStart error (line 153)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x6F},
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for unicode readSizeAndStart failure")
		}
	})

	// Unicode string (0x6x): 0x62 claims 2 chars (4 bytes) but only 2 content bytes present.
	t.Run("unicode string content truncated (line 157)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0x62, 0x00, 0x41}, // 2 chars = 4 bytes, only 2 present
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated unicode string")
		}
	})

	// Array (0xAx): 0xAF triggers extended size; only 1 byte present.
	t.Run("array readSizeAndStart error (line 168)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0xAF},
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for array readSizeAndStart failure")
		}
	})

	// Array (0xAx): 0xA1 claims 1 element ref but no ref byte follows.
	t.Run("array ref truncated (line 174)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0xA1}, // array marker, ref byte missing
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated array ref")
		}
	})

	// Dict (0xDx): 0xDF triggers extended size; only 1 byte present.
	t.Run("dict readSizeAndStart error (line 188)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0xDF},
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for dict readSizeAndStart failure")
		}
	})

	// Dict (0xDx): 0xD1 claims 1 entry (key+val refs) but no ref bytes follow.
	t.Run("dict ref truncated (line 197)", func(t *testing.T) {
		ctx := &bplistContext{
			data:          []byte{0xD1}, // dict with 1 entry, no ref bytes
			offsets:       []int{0},
			objectRefSize: 1,
			numObjects:    1,
		}
		_, err := ctx.parseObject(0)
		if err == nil {
			t.Error("expected error for truncated dict ref")
		}
	})
}

// TestReadSizeAndStartDataTruncated covers the "extended size data truncated" path (line 240).
// The size marker is valid but not enough bytes follow for the integer value.
func TestReadSizeAndStartDataTruncated(t *testing.T) {
	// 0x5F at offset 0 → objInfo=0xF → extended size
	// data[1]=0x11 → valid int marker (sizeMarker>>4=1), sizeBytes=1<<1=2
	// start=2, start+sizeBytes=4 > len(data)=3 → hits line 240
	ctx := &bplistContext{
		data:          []byte{0x5F, 0x11, 0x00}, // size marker + 1 int byte (need 2)
		offsets:       []int{0},
		objectRefSize: 1,
		numObjects:    1,
	}
	_, err := ctx.parseObject(0)
	if err == nil {
		t.Error("expected error for extended size data truncated")
	}
}
