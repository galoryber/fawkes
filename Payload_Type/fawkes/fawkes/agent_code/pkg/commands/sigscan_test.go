package commands

import (
	"encoding/binary"
	"testing"
)

func TestParseHexPatternBasic(t *testing.T) {
	values, wildcards, err := parseHexPattern("33 F6 89 77 00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x33, 0xF6, 0x89, 0x77, 0x00}
	if len(values) != len(want) {
		t.Fatalf("len mismatch: got %d, want %d", len(values), len(want))
	}
	for i, v := range want {
		if values[i] != v {
			t.Errorf("values[%d] = 0x%02X, want 0x%02X", i, values[i], v)
		}
		if wildcards[i] {
			t.Errorf("wildcards[%d] = true, want false", i)
		}
	}
}

func TestParseHexPatternWildcards(t *testing.T) {
	values, wildcards, err := parseHexPattern("4C 8B 05 ?? ?? ?? ??")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 7 {
		t.Fatalf("len = %d, want 7", len(values))
	}
	if values[0] != 0x4C || values[1] != 0x8B || values[2] != 0x05 {
		t.Errorf("anchor bytes wrong: %02X %02X %02X", values[0], values[1], values[2])
	}
	for i := 3; i < 7; i++ {
		if !wildcards[i] {
			t.Errorf("wildcards[%d] = false, want true", i)
		}
		if values[i] != 0x00 {
			t.Errorf("values[%d] under wildcard = 0x%02X, want 0x00", i, values[i])
		}
	}
}

func TestParseHexPatternMixedCase(t *testing.T) {
	values, _, err := parseHexPattern("aB cD 0F")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if values[0] != 0xAB || values[1] != 0xCD || values[2] != 0x0F {
		t.Errorf("mixed case parse failed: %02X %02X %02X", values[0], values[1], values[2])
	}
}

func TestParseHexPatternMimikatzSignature(t *testing.T) {
	// LogonSessionList signature from research:
	// 33 F6 89 77 00 4C 8D 4D D0 4C 8B 05 ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ??
	sig := "33 F6 89 77 00 4C 8D 4D D0 4C 8B 05 ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ??"
	values, wildcards, err := parseHexPattern(sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 23 {
		t.Fatalf("expected 23 bytes, got %d", len(values))
	}
	wildcardCount := 0
	for _, w := range wildcards {
		if w {
			wildcardCount++
		}
	}
	if wildcardCount != 8 {
		t.Errorf("expected 8 wildcard bytes, got %d", wildcardCount)
	}
	// Spot-check anchor bytes
	if values[0] != 0x33 || values[16] != 0x48 || values[17] != 0x8D || values[18] != 0x1D {
		t.Errorf("anchor bytes wrong: 0=%02X 16=%02X 17=%02X 18=%02X",
			values[0], values[16], values[17], values[18])
	}
}

func TestParseHexPatternErrors(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"odd token", "33 F"},
		{"too long token", "FFFF"},
		{"invalid digit", "33 ZZ"},
		{"single ?", "33 ?"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := parseHexPattern(c.s); err == nil {
				t.Errorf("expected error for %q, got nil", c.s)
			}
		})
	}
}

func TestFindPatternLiteral(t *testing.T) {
	hay := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	values, wildcards, _ := parseHexPattern("22 33 44")
	got := findPattern(hay, values, wildcards)
	if got != 2 {
		t.Errorf("findPattern = %d, want 2", got)
	}
}

func TestFindPatternWithWildcards(t *testing.T) {
	hay := []byte{0xAB, 0xCD, 0x4C, 0x8B, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x90}
	values, wildcards, _ := parseHexPattern("4C 8B 05 ?? ?? ?? ??")
	got := findPattern(hay, values, wildcards)
	if got != 2 {
		t.Errorf("findPattern = %d, want 2", got)
	}
}

func TestFindPatternNoMatch(t *testing.T) {
	hay := []byte{0x00, 0x11, 0x22, 0x33}
	values, wildcards, _ := parseHexPattern("FF FF")
	got := findPattern(hay, values, wildcards)
	if got != -1 {
		t.Errorf("findPattern = %d, want -1", got)
	}
}

func TestFindPatternAtStart(t *testing.T) {
	hay := []byte{0x33, 0xF6, 0x00, 0x00}
	values, wildcards, _ := parseHexPattern("33 F6")
	got := findPattern(hay, values, wildcards)
	if got != 0 {
		t.Errorf("findPattern = %d, want 0", got)
	}
}

func TestFindPatternAtEnd(t *testing.T) {
	hay := []byte{0x00, 0x00, 0x33, 0xF6}
	values, wildcards, _ := parseHexPattern("33 F6")
	got := findPattern(hay, values, wildcards)
	if got != 2 {
		t.Errorf("findPattern = %d, want 2", got)
	}
}

func TestFindPatternHaystackTooShort(t *testing.T) {
	hay := []byte{0x33}
	values, wildcards, _ := parseHexPattern("33 F6 89")
	got := findPattern(hay, values, wildcards)
	if got != -1 {
		t.Errorf("findPattern with too-short haystack = %d, want -1", got)
	}
}

func TestFindPatternEmptyPattern(t *testing.T) {
	hay := []byte{0x33, 0xF6}
	got := findPattern(hay, nil, nil)
	if got != -1 {
		t.Errorf("findPattern with empty pattern = %d, want -1", got)
	}
}

func TestFindAllPatternsMultipleHits(t *testing.T) {
	hay := []byte{0xAA, 0xBB, 0xAA, 0xBB, 0xCC, 0xAA, 0xBB}
	values, wildcards, _ := parseHexPattern("AA BB")
	hits := findAllPatterns(hay, values, wildcards, 0)
	if len(hits) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(hits))
	}
	want := []int{0, 2, 5}
	for i, w := range want {
		if hits[i] != w {
			t.Errorf("hits[%d] = %d, want %d", i, hits[i], w)
		}
	}
}

func TestFindAllPatternsMaxLimit(t *testing.T) {
	hay := []byte{0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB}
	values, wildcards, _ := parseHexPattern("AA BB")
	hits := findAllPatterns(hay, values, wildcards, 2)
	if len(hits) != 2 {
		t.Errorf("expected 2 matches with max=2, got %d", len(hits))
	}
}

func TestFindAllPatternsNoMatch(t *testing.T) {
	hay := []byte{0x00, 0x11, 0x22}
	values, wildcards, _ := parseHexPattern("FF FF")
	hits := findAllPatterns(hay, values, wildcards, 0)
	if len(hits) != 0 {
		t.Errorf("expected 0 matches, got %d", len(hits))
	}
}

func TestResolveRIPRelativePositive(t *testing.T) {
	// Synthetic instruction: MOV REG, [RIP+offset]
	//   bytes: 4C 8B 05 [d0 d1 d2 d3]   instrLen=7, dispOffset=3
	// disp32 = 0x10 (16) → target = instrStart + instrLen + 0x10
	hay := make([]byte, 64)
	hay[0] = 0x4C
	hay[1] = 0x8B
	hay[2] = 0x05
	binary.LittleEndian.PutUint32(hay[3:7], 0x10)
	target, disp, ok := resolveRIPRelative(hay, 0, 3, 7)
	if !ok {
		t.Fatalf("expected ok, got false")
	}
	if disp != 0x10 {
		t.Errorf("disp = %d, want 0x10", disp)
	}
	wantTarget := 0 + 7 + 0x10
	if target != wantTarget {
		t.Errorf("target = %d, want %d", target, wantTarget)
	}
}

func TestResolveRIPRelativeNegative(t *testing.T) {
	hay := make([]byte, 64)
	const start = 32
	hay[start+0] = 0x48
	hay[start+1] = 0x8D
	hay[start+2] = 0x1D
	// disp = -8 (two's complement: 0xFFFFFFF8)
	binary.LittleEndian.PutUint32(hay[start+3:start+7], 0xFFFFFFF8)
	target, disp, ok := resolveRIPRelative(hay, start, 3, 7)
	if !ok {
		t.Fatalf("expected ok, got false")
	}
	if disp != -8 {
		t.Errorf("disp = %d, want -8", disp)
	}
	wantTarget := start + 7 - 8
	if target != wantTarget {
		t.Errorf("target = %d, want %d", target, wantTarget)
	}
}

func TestResolveRIPRelativeOutOfHaystack(t *testing.T) {
	hay := make([]byte, 16)
	hay[0] = 0x4C
	hay[1] = 0x8B
	hay[2] = 0x05
	// Large positive disp puts target beyond haystack length
	binary.LittleEndian.PutUint32(hay[3:7], 0x1000)
	target, disp, ok := resolveRIPRelative(hay, 0, 3, 7)
	if ok {
		t.Errorf("expected ok=false (target outside haystack), got true target=%d disp=%d", target, disp)
	}
	if disp != 0x1000 {
		t.Errorf("disp = %d, want 0x1000", disp)
	}
}

func TestResolveRIPRelativeInvalidArgs(t *testing.T) {
	hay := make([]byte, 16)
	cases := []struct {
		name                            string
		instrStart, dispOffset, instrLen int
	}{
		{"negative instrStart", -1, 3, 7},
		{"negative dispOffset", 0, -1, 7},
		{"zero instrLen", 0, 3, 0},
		{"disp past instrLen", 0, 5, 7},
		{"disp past haystack", 13, 3, 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, ok := resolveRIPRelative(hay, c.instrStart, c.dispOffset, c.instrLen); ok {
				t.Errorf("expected ok=false for %s, got true", c.name)
			}
		})
	}
}
