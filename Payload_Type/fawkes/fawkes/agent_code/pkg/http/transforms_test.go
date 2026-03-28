package http

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBase64Transform(t *testing.T) {
	tr := &Base64Transform{}
	input := []byte("hello world")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(encoded) != "aGVsbG8gd29ybGQ=" {
		t.Errorf("Encode = %q, want %q", encoded, "aGVsbG8gd29ybGQ=")
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("Decode = %q, want %q", decoded, input)
	}
}

func TestHexTransform(t *testing.T) {
	tr := &HexTransform{}
	input := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(encoded) != "deadbeef" {
		t.Errorf("Encode = %q, want %q", encoded, "deadbeef")
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestPrependTransform(t *testing.T) {
	tr := &PrependTransform{Prefix: []byte("PREFIX_")}
	input := []byte("data")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(encoded) != "PREFIX_data" {
		t.Errorf("Encode = %q", encoded)
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed: %q", decoded)
	}
}

func TestAppendTransform(t *testing.T) {
	tr := &AppendTransform{Suffix: []byte("_END")}
	input := []byte("data")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(encoded) != "data_END" {
		t.Errorf("Encode = %q", encoded)
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed: %q", decoded)
	}
}

func TestXORTransform(t *testing.T) {
	tr := &XORTransform{Key: []byte{0xFF}}
	input := []byte{0x00, 0x41, 0x42}

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	expected := []byte{0xFF, 0xBE, 0xBD}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("Encode = %x, want %x", encoded, expected)
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestXORTransformRepeatingKey(t *testing.T) {
	tr := &XORTransform{Key: []byte{0xAB, 0xCD}}
	input := []byte{0x01, 0x02, 0x03, 0x04}

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	expected := []byte{0x01 ^ 0xAB, 0x02 ^ 0xCD, 0x03 ^ 0xAB, 0x04 ^ 0xCD}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("Encode = %x, want %x", encoded, expected)
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestGzipTransform(t *testing.T) {
	tr := &GzipTransform{}
	input := []byte("the quick brown fox jumps over the lazy dog")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Gzip should compress this string
	if len(encoded) >= len(input) {
		t.Logf("warning: gzip didn't reduce size (%d >= %d)", len(encoded), len(input))
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestGzipTransformLargePayload(t *testing.T) {
	tr := &GzipTransform{}
	// Repetitive data compresses well
	input := bytes.Repeat([]byte("AAAA"), 10000)

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(encoded) >= len(input)/2 {
		t.Errorf("gzip compression ratio too low: %d -> %d", len(input), len(encoded))
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestMaskTransformPNG(t *testing.T) {
	mask := fileMasks["png"]
	input := []byte("encrypted_agent_data_here")

	encoded, err := mask.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Should start with PNG magic bytes
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47}
	if !bytes.HasPrefix(encoded, pngMagic) {
		t.Errorf("encoded data doesn't start with PNG magic: %x", encoded[:4])
	}

	// Should end with IEND
	iend := []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}
	if !bytes.HasSuffix(encoded, iend) {
		t.Errorf("encoded data doesn't end with IEND marker")
	}

	decoded, err := mask.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed: %q", decoded)
	}
}

func TestMaskTransformGIF(t *testing.T) {
	mask := fileMasks["gif"]
	input := []byte("test_data")

	encoded, err := mask.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.HasPrefix(encoded, []byte("GIF89a")) {
		t.Errorf("doesn't start with GIF89a")
	}

	decoded, err := mask.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestMaskTransformJPEG(t *testing.T) {
	mask := fileMasks["jpeg"]
	input := []byte("jpeg_test_data")

	encoded, err := mask.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// JPEG magic bytes
	if !bytes.HasPrefix(encoded, []byte{0xFF, 0xD8, 0xFF}) {
		t.Errorf("doesn't start with JPEG magic")
	}
	// JPEG EOI
	if !bytes.HasSuffix(encoded, []byte{0xFF, 0xD9}) {
		t.Errorf("doesn't end with JPEG EOI")
	}

	decoded, err := mask.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestMaskTransformPDF(t *testing.T) {
	mask := fileMasks["pdf"]
	input := []byte("pdf_test_data")

	encoded, err := mask.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.HasPrefix(encoded, []byte("%PDF-1.4")) {
		t.Errorf("doesn't start with PDF header")
	}
	if !bytes.HasSuffix(encoded, []byte("%%EOF")) {
		t.Errorf("doesn't end with %%EOF")
	}

	decoded, err := mask.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestNetBIOSTransform(t *testing.T) {
	tr := &NetBIOSTransform{}
	input := []byte{0x41, 0x42} // "AB"

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// 0x41 = 4,1 → 'E','B'  |  0x42 = 4,2 → 'E','C'
	expected := []byte{'E', 'B', 'E', 'C'}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("Encode = %q, want %q", encoded, expected)
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestNetBIOSTransformOddLength(t *testing.T) {
	tr := &NetBIOSTransform{}
	_, err := tr.Decode([]byte("ABC"))
	if err == nil {
		t.Error("expected error for odd-length input")
	}
}

func TestTransformChain(t *testing.T) {
	chain := NewTransformChain(
		&Base64Transform{},
		&PrependTransform{Prefix: []byte("START:")},
		&AppendTransform{Suffix: []byte(":END")},
	)

	input := []byte("test_message")

	encoded, err := chain.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Should be: base64(input) → prepend("START:") → append(":END")
	if !bytes.HasPrefix(encoded, []byte("START:")) {
		t.Errorf("missing START prefix: %q", encoded)
	}
	if !bytes.HasSuffix(encoded, []byte(":END")) {
		t.Errorf("missing END suffix: %q", encoded)
	}

	decoded, err := chain.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed: got %q, want %q", decoded, input)
	}
}

func TestTransformChainEmpty(t *testing.T) {
	chain := NewTransformChain()
	input := []byte("unchanged")

	encoded, err := chain.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, input) {
		t.Errorf("empty chain should not modify data")
	}

	decoded, err := chain.Decode(input)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("empty chain should not modify data")
	}
}

func TestTransformChainNil(t *testing.T) {
	var chain *TransformChain
	input := []byte("unchanged")

	encoded, err := chain.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, input) {
		t.Errorf("nil chain should not modify data")
	}

	decoded, err := chain.Decode(input)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("nil chain should not modify data")
	}
}

func TestParseTransformChainEmpty(t *testing.T) {
	chain, err := ParseTransformChain("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chain != nil {
		t.Error("expected nil chain for empty spec")
	}
}

func TestParseTransformChainSingle(t *testing.T) {
	tests := []struct {
		spec  string
		input []byte
	}{
		{"base64", []byte("hello")},
		{"hex", []byte{0xDE, 0xAD}},
		{"gzip", []byte("compress me")},
		{"netbios", []byte{0x41}},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			chain, err := ParseTransformChain(tt.spec)
			if err != nil {
				t.Fatalf("ParseTransformChain: %v", err)
			}
			encoded, err := chain.Encode(tt.input)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			decoded, err := chain.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(decoded, tt.input) {
				t.Errorf("roundtrip failed for %q", tt.spec)
			}
		})
	}
}

func TestParseTransformChainWithArgs(t *testing.T) {
	tests := []struct {
		spec  string
		input []byte
	}{
		{"prepend:DEADBEEF", []byte("data")},
		{"append:CAFEBABE", []byte("data")},
		{"xor:FF", []byte{0x41, 0x42}},
		{"mask:png", []byte("image_data")},
		{"mask:gif", []byte("gif_data")},
		{"mask:jpeg", []byte("jpeg_data")},
		{"mask:pdf", []byte("pdf_data")},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			chain, err := ParseTransformChain(tt.spec)
			if err != nil {
				t.Fatalf("ParseTransformChain(%q): %v", tt.spec, err)
			}
			encoded, err := chain.Encode(tt.input)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			decoded, err := chain.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(decoded, tt.input) {
				t.Errorf("roundtrip failed for %q", tt.spec)
			}
		})
	}
}

func TestParseTransformChainMultiple(t *testing.T) {
	spec := "gzip,base64,prepend:2F2F,append:0A"
	chain, err := ParseTransformChain(spec)
	if err != nil {
		t.Fatalf("ParseTransformChain: %v", err)
	}

	input := bytes.Repeat([]byte("AAAA"), 100)
	encoded, err := chain.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Should start with "//" (0x2F2F) and end with "\n" (0x0A)
	if !bytes.HasPrefix(encoded, []byte("//")) {
		t.Errorf("missing // prefix")
	}
	if !bytes.HasSuffix(encoded, []byte("\n")) {
		t.Errorf("missing newline suffix")
	}

	decoded, err := chain.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestParseTransformChainErrors(t *testing.T) {
	tests := []struct {
		spec string
	}{
		{"unknown"},
		{"prepend:"},
		{"prepend:GG"}, // invalid hex
		{"append:"},
		{"xor:"},
		{"mask:bmp"}, // unsupported mask type
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			_, err := ParseTransformChain(tt.spec)
			if err == nil {
				t.Errorf("expected error for spec %q", tt.spec)
			}
		})
	}
}

func TestPrependTransformBinaryData(t *testing.T) {
	prefix, _ := hex.DecodeString("89504E47")
	tr := &PrependTransform{Prefix: prefix}
	input := []byte("binary_payload")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.HasPrefix(encoded, prefix) {
		t.Errorf("missing binary prefix")
	}

	decoded, err := tr.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestTransformChainComplexRoundtrip(t *testing.T) {
	// Realistic transform chain: gzip → mask as PNG
	chain := NewTransformChain(
		&GzipTransform{},
		fileMasks["png"],
	)

	// Simulate a realistic agent message (base64 encoded)
	input := []byte("YWdlbnRfbWVzc2FnZV9kYXRhX3dpdGhfZW5jcnlwdGVkX3BheWxvYWQ=")

	encoded, err := chain.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Verify PNG magic bytes
	if !bytes.HasPrefix(encoded, []byte{0x89, 0x50, 0x4E, 0x47}) {
		t.Error("output doesn't look like a PNG")
	}

	decoded, err := chain.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed")
	}
}

func TestXORTransformEmptyKey(t *testing.T) {
	tr := &XORTransform{Key: []byte{}}
	input := []byte("unchanged")

	encoded, err := tr.Encode(input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded, input) {
		t.Error("empty key should not modify data")
	}
}
