package httpx

import (
	"encoding/base64"
	"fmt"
)

// Transform represents a single transform step in the httpx pipeline.
type Transform struct {
	Action string `json:"action"`
	Value  string `json:"value"`
}

// ApplyTransformsForward applies transforms in forward order (index 0, 1, 2...).
// Used by the agent when sending: applies client transforms to build the request.
func ApplyTransformsForward(data []byte, transforms []Transform) ([]byte, error) {
	var err error
	for _, t := range transforms {
		data, err = applyTransform(data, t)
		if err != nil {
			return nil, fmt.Errorf("transform %s forward: %w", t.Action, err)
		}
	}
	return data, nil
}

// ApplyTransformsReverse applies transforms in reverse order (index N-1, N-2...).
// Used by the agent when receiving: reverses server transforms to recover the response.
func ApplyTransformsReverse(data []byte, transforms []Transform) ([]byte, error) {
	var err error
	for i := len(transforms) - 1; i >= 0; i-- {
		data, err = reverseTransform(data, transforms[i])
		if err != nil {
			return nil, fmt.Errorf("transform %s reverse: %w", transforms[i].Action, err)
		}
	}
	return data, nil
}

// applyTransform applies a single transform in the forward (encode) direction.
func applyTransform(data []byte, t Transform) ([]byte, error) {
	switch t.Action {
	case "base64":
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(dst, data)
		return dst, nil
	case "base64url":
		dst := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
		base64.URLEncoding.Encode(dst, data)
		return dst, nil
	case "xor":
		return xorBytes(data, []byte(t.Value)), nil
	case "netbios":
		return netbiosEncode(data, 'a'), nil
	case "netbiosu":
		return netbiosEncode(data, 'A'), nil
	case "prepend":
		return append([]byte(t.Value), data...), nil
	case "append":
		return append(data, []byte(t.Value)...), nil
	default:
		return nil, fmt.Errorf("unknown transform action: %s", t.Action)
	}
}

// reverseTransform reverses a single transform (decode direction).
func reverseTransform(data []byte, t Transform) ([]byte, error) {
	switch t.Action {
	case "base64":
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(dst, data)
		if err != nil {
			return nil, err
		}
		return dst[:n], nil
	case "base64url":
		dst := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
		n, err := base64.URLEncoding.Decode(dst, data)
		if err != nil {
			return nil, err
		}
		return dst[:n], nil
	case "xor":
		return xorBytes(data, []byte(t.Value)), nil
	case "netbios":
		return netbiosDecode(data, 'a')
	case "netbiosu":
		return netbiosDecode(data, 'A')
	case "prepend":
		prefixLen := len(t.Value)
		if len(data) < prefixLen {
			return nil, fmt.Errorf("data too short to strip prepend of length %d", prefixLen)
		}
		return data[prefixLen:], nil
	case "append":
		suffixLen := len(t.Value)
		if len(data) < suffixLen {
			return nil, fmt.Errorf("data too short to strip append of length %d", suffixLen)
		}
		return data[:len(data)-suffixLen], nil
	default:
		return nil, fmt.Errorf("unknown transform action: %s", t.Action)
	}
}

// xorBytes XOR-encodes/decodes data with a repeating key.
func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

// netbiosEncode splits each byte into two nibbles, adding baseChar to each.
// Doubles the data size. baseChar='a' for lowercase, 'A' for uppercase.
func netbiosEncode(data []byte, baseChar byte) []byte {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = (b >> 4) + baseChar
		result[i*2+1] = (b & 0x0F) + baseChar
	}
	return result
}

// netbiosDecode reverses NetBIOS encoding: takes pairs of chars, subtracts
// baseChar, and recombines the nibbles into original bytes.
func netbiosDecode(data []byte, baseChar byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("netbios data must be even length, got %d", len(data))
	}
	result := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		high := data[i] - baseChar
		low := data[i+1] - baseChar
		result[i/2] = (high << 4) | low
	}
	return result, nil
}
