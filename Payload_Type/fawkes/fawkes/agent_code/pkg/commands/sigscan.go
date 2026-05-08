package commands

// Signature scanning helpers — used to locate well-known structures in remote
// process memory by matching mimikatz-style hex patterns with `??` wildcards.
//
// Foundation for hashdump in-situ Phase 2 (LSASS LogonSessionList lookup) and
// other techniques that need to dereference RIP-relative globals in mapped
// modules. Pure Go so the parser/scanner runs on every supported platform and
// can be unit-tested without a Windows host.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// parseHexPattern converts a mimikatz-style signature ("33 F6 ?? ?? 4C 8D")
// into a byte slice plus a parallel wildcard mask. Whitespace between tokens is
// ignored. Each token must be either two hex digits or two question marks; the
// returned values slice has 0x00 in wildcard positions, and the mask slice is
// true wherever the original byte was a wildcard.
func parseHexPattern(s string) ([]byte, []bool, error) {
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return nil, nil, fmt.Errorf("empty pattern")
	}
	values := make([]byte, len(tokens))
	wildcards := make([]bool, len(tokens))
	for i, tok := range tokens {
		if len(tok) != 2 {
			return nil, nil, fmt.Errorf("token %q at position %d: expected 2 chars, got %d", tok, i, len(tok))
		}
		if tok == "??" {
			wildcards[i] = true
			continue
		}
		v, err := parseHexByte(tok)
		if err != nil {
			return nil, nil, fmt.Errorf("token %q at position %d: %v", tok, i, err)
		}
		values[i] = v
	}
	return values, wildcards, nil
}

func parseHexByte(tok string) (byte, error) {
	hi, err := hexNibble(tok[0])
	if err != nil {
		return 0, err
	}
	lo, err := hexNibble(tok[1])
	if err != nil {
		return 0, err
	}
	return hi<<4 | lo, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit %q", c)
	}
}

// findPattern returns the first offset in haystack where pattern (with
// wildcards) matches, or -1 if no match. Pattern len must equal mask len.
func findPattern(haystack []byte, pattern []byte, wildcards []bool) int {
	if len(pattern) == 0 || len(pattern) != len(wildcards) {
		return -1
	}
	if len(haystack) < len(pattern) {
		return -1
	}
	last := len(haystack) - len(pattern)
	for i := 0; i <= last; i++ {
		if matchAt(haystack, i, pattern, wildcards) {
			return i
		}
	}
	return -1
}

// findAllPatterns returns up to max offsets in haystack where the pattern
// matches. A non-positive max returns every match.
func findAllPatterns(haystack []byte, pattern []byte, wildcards []bool, max int) []int {
	if len(pattern) == 0 || len(pattern) != len(wildcards) || len(haystack) < len(pattern) {
		return nil
	}
	last := len(haystack) - len(pattern)
	var out []int
	for i := 0; i <= last; i++ {
		if matchAt(haystack, i, pattern, wildcards) {
			out = append(out, i)
			if max > 0 && len(out) >= max {
				return out
			}
		}
	}
	return out
}

func matchAt(haystack []byte, offset int, pattern []byte, wildcards []bool) bool {
	for j, b := range pattern {
		if wildcards[j] {
			continue
		}
		if haystack[offset+j] != b {
			return false
		}
	}
	return true
}

// resolveRIPRelative decodes a 4-byte RIP-relative displacement embedded in an
// x86-64 instruction. Inputs:
//
//   - haystack:    bytes containing the matched instruction
//   - instrStart:  offset (within haystack) of the first byte of the instruction
//   - dispOffset:  offset (within the instruction) of the disp32 field
//   - instrLen:    total length of the instruction
//
// Returns the haystack offset that the displacement targets, plus the raw
// signed displacement. ok is false when the displacement field would extend
// past the haystack or the resolved target is outside it. Callers reading from
// a memory snapshot (rather than a full module) should treat a false `ok` as
// "target lies outside the captured window" and re-read a wider range.
func resolveRIPRelative(haystack []byte, instrStart, dispOffset, instrLen int) (target int, disp int32, ok bool) {
	if instrStart < 0 || dispOffset < 0 || instrLen <= 0 {
		return 0, 0, false
	}
	if dispOffset+4 > instrLen {
		return 0, 0, false
	}
	dispStart := instrStart + dispOffset
	if dispStart < 0 || dispStart+4 > len(haystack) {
		return 0, 0, false
	}
	disp = int32(binary.LittleEndian.Uint32(haystack[dispStart : dispStart+4]))
	target = instrStart + instrLen + int(disp)
	if target < 0 || target > len(haystack) {
		return target, disp, false
	}
	return target, disp, true
}
