package httpx

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestXorBytes(t *testing.T) {
	data := []byte("hello world")
	key := []byte("secret")

	encoded := xorBytes(data, key)
	if bytes.Equal(encoded, data) {
		t.Fatal("XOR should produce different output")
	}

	decoded := xorBytes(encoded, key)
	if !bytes.Equal(decoded, data) {
		t.Fatalf("XOR roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestXorBytesEmptyKey(t *testing.T) {
	data := []byte("hello")
	result := xorBytes(data, nil)
	if !bytes.Equal(result, data) {
		t.Fatal("empty key should return copy of data")
	}
}

func TestNetbiosEncodeDecode(t *testing.T) {
	data := []byte{0x00, 0xFF, 0x41, 0xAB}

	// Lowercase
	encoded := netbiosEncode(data, 'a')
	if len(encoded) != len(data)*2 {
		t.Fatalf("netbios encode should double length: got %d, want %d", len(encoded), len(data)*2)
	}
	decoded, err := netbiosDecode(encoded, 'a')
	if err != nil {
		t.Fatalf("netbios decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("netbios roundtrip failed: got %v, want %v", decoded, data)
	}

	// Uppercase
	encodedU := netbiosEncode(data, 'A')
	decodedU, err := netbiosDecode(encodedU, 'A')
	if err != nil {
		t.Fatalf("netbiosu decode failed: %v", err)
	}
	if !bytes.Equal(decodedU, data) {
		t.Fatalf("netbiosu roundtrip failed: got %v, want %v", decodedU, data)
	}
}

func TestNetbiosDecodeOddLength(t *testing.T) {
	_, err := netbiosDecode([]byte("abc"), 'a')
	if err == nil {
		t.Fatal("expected error for odd-length netbios data")
	}
}

func TestApplyTransformBase64(t *testing.T) {
	data := []byte("test data for base64")
	transform := Transform{Action: "base64"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("base64 encode failed: %v", err)
	}

	expected := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(expected, data)
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("base64 encode mismatch: got %q, want %q", encoded, expected)
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("base64 roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformBase64URL(t *testing.T) {
	data := []byte("test data with +/= chars")
	transform := Transform{Action: "base64url"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("base64url encode failed: %v", err)
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("base64url decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("base64url roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformXOR(t *testing.T) {
	data := []byte("sensitive payload data")
	transform := Transform{Action: "xor", Value: "mykey123"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("xor encode failed: %v", err)
	}
	if bytes.Equal(encoded, data) {
		t.Fatal("xor should change data")
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("xor decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("xor roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformPrepend(t *testing.T) {
	data := []byte("actual-data")
	transform := Transform{Action: "prepend", Value: "JUNK-PREFIX-"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("prepend failed: %v", err)
	}
	if string(encoded) != "JUNK-PREFIX-actual-data" {
		t.Fatalf("prepend result wrong: got %q", encoded)
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("prepend reverse failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("prepend roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformAppend(t *testing.T) {
	data := []byte("actual-data")
	transform := Transform{Action: "append", Value: "-JUNK-SUFFIX"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}
	if string(encoded) != "actual-data-JUNK-SUFFIX" {
		t.Fatalf("append result wrong: got %q", encoded)
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("append reverse failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("append roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformNetbios(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	transform := Transform{Action: "netbios"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("netbios encode failed: %v", err)
	}
	if len(encoded) != 8 {
		t.Fatalf("netbios should double length: got %d", len(encoded))
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("netbios decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("netbios roundtrip failed: got %v, want %v", decoded, data)
	}
}

func TestApplyTransformNetbiosU(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43}
	transform := Transform{Action: "netbiosu"}

	encoded, err := applyTransform(data, transform)
	if err != nil {
		t.Fatalf("netbiosu encode failed: %v", err)
	}

	decoded, err := reverseTransform(encoded, transform)
	if err != nil {
		t.Fatalf("netbiosu decode failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("netbiosu roundtrip failed: got %v, want %v", decoded, data)
	}
}

func TestApplyTransformUnknown(t *testing.T) {
	_, err := applyTransform([]byte("data"), Transform{Action: "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown transform")
	}
}

func TestApplyTransformsForwardReverse(t *testing.T) {
	data := []byte("mythic-message-payload-uuid-encrypted-data")

	transforms := []Transform{
		{Action: "base64"},
		{Action: "xor", Value: "secretkey"},
		{Action: "prepend", Value: "PREFIX"},
		{Action: "append", Value: "SUFFIX"},
	}

	encoded, err := ApplyTransformsForward(data, transforms)
	if err != nil {
		t.Fatalf("forward transforms failed: %v", err)
	}

	decoded, err := ApplyTransformsReverse(encoded, transforms)
	if err != nil {
		t.Fatalf("reverse transforms failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("forward/reverse roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestApplyTransformsComplexChain(t *testing.T) {
	data := []byte("complex-message-with-binary-\x00\x01\x02-content")

	transforms := []Transform{
		{Action: "xor", Value: "key1"},
		{Action: "netbios"},
		{Action: "base64url"},
		{Action: "prepend", Value: "data="},
		{Action: "append", Value: "&end=1"},
	}

	encoded, err := ApplyTransformsForward(data, transforms)
	if err != nil {
		t.Fatalf("forward transforms failed: %v", err)
	}

	decoded, err := ApplyTransformsReverse(encoded, transforms)
	if err != nil {
		t.Fatalf("reverse transforms failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("complex chain roundtrip failed")
	}
}

func TestApplyTransformsEmpty(t *testing.T) {
	data := []byte("unchanged")

	result, err := ApplyTransformsForward(data, nil)
	if err != nil {
		t.Fatalf("empty forward failed: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Fatal("empty transforms should return data unchanged")
	}

	result, err = ApplyTransformsReverse(data, nil)
	if err != nil {
		t.Fatalf("empty reverse failed: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Fatal("empty transforms should return data unchanged")
	}
}

func TestPrependReverseTooShort(t *testing.T) {
	_, err := reverseTransform([]byte("ab"), Transform{Action: "prepend", Value: "abcdef"})
	if err == nil {
		t.Fatal("expected error for data shorter than prepend value")
	}
}

func TestAppendReverseTooShort(t *testing.T) {
	_, err := reverseTransform([]byte("ab"), Transform{Action: "append", Value: "abcdef"})
	if err == nil {
		t.Fatal("expected error for data shorter than append value")
	}
}
