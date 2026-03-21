//go:build !windows

package commands

import (
	"encoding/binary"
	"math"
	"testing"
)

// buildBplist constructs a minimal valid binary plist from objects.
// Each object is a raw byte slice. Returns the complete bplist00 file.
func buildBplist(objects [][]byte, topObject int) []byte {
	var body []byte
	offsets := make([]int, len(objects))
	baseOffset := 8 // "bplist00" header

	for i, obj := range objects {
		offsets[i] = baseOffset + len(body)
		body = append(body, obj...)
	}

	// Determine offset size
	maxOffset := baseOffset + len(body)
	offsetSize := 1
	if maxOffset > 0xFF {
		offsetSize = 2
	}
	if maxOffset > 0xFFFF {
		offsetSize = 4
	}

	// Object ref size
	objectRefSize := 1
	if len(objects) > 0xFF {
		objectRefSize = 2
	}

	// Build offset table
	offsetTableOffset := baseOffset + len(body)
	var offsetTable []byte
	for _, off := range offsets {
		offsetTable = append(offsetTable, writeSizedInt(off, offsetSize)...)
	}

	// Build trailer (32 bytes)
	var trailer [32]byte
	trailer[6] = byte(offsetSize)
	trailer[7] = byte(objectRefSize)
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:24], uint64(topObject))
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTableOffset))

	var result []byte
	result = append(result, []byte("bplist00")...)
	result = append(result, body...)
	result = append(result, offsetTable...)
	result = append(result, trailer[:]...)
	return result
}

func writeSizedInt(val, size int) []byte {
	b := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		b[i] = byte(val & 0xFF)
		val >>= 8
	}
	return b
}

func bplistBool(v bool) []byte {
	if v {
		return []byte{0x09}
	}
	return []byte{0x08}
}

func bplistNull() []byte {
	return []byte{0x00}
}

func bplistInt(v int64) []byte {
	if v >= 0 && v <= 0xFF {
		return []byte{0x10, byte(v)}
	}
	if v >= 0 && v <= 0xFFFF {
		b := make([]byte, 3)
		b[0] = 0x11
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return b
	}
	b := make([]byte, 5)
	b[0] = 0x12
	binary.BigEndian.PutUint32(b[1:], uint32(v))
	return b
}

func bplistString(s string) []byte {
	if len(s) < 15 {
		return append([]byte{0x50 | byte(len(s))}, []byte(s)...)
	}
	// Extended size
	sizeInt := bplistInt(int64(len(s)))
	result := []byte{0x5F}
	result = append(result, sizeInt...)
	result = append(result, []byte(s)...)
	return result
}

func bplistData(d []byte) []byte {
	if len(d) < 15 {
		return append([]byte{0x40 | byte(len(d))}, d...)
	}
	sizeInt := bplistInt(int64(len(d)))
	result := []byte{0x4F}
	result = append(result, sizeInt...)
	result = append(result, d...)
	return result
}

func bplistArray(refs ...int) []byte {
	if len(refs) < 15 {
		result := []byte{0xA0 | byte(len(refs))}
		for _, r := range refs {
			result = append(result, byte(r))
		}
		return result
	}
	sizeInt := bplistInt(int64(len(refs)))
	result := []byte{0xAF}
	result = append(result, sizeInt...)
	for _, r := range refs {
		result = append(result, byte(r))
	}
	return result
}

func bplistDict(keyRefs, valRefs []int) []byte {
	if len(keyRefs) != len(valRefs) {
		panic("mismatched key/value refs")
	}
	count := len(keyRefs)
	var result []byte
	if count < 15 {
		result = []byte{0xD0 | byte(count)}
	} else {
		sizeInt := bplistInt(int64(count))
		result = []byte{0xDF}
		result = append(result, sizeInt...)
	}
	for _, r := range keyRefs {
		result = append(result, byte(r))
	}
	for _, r := range valRefs {
		result = append(result, byte(r))
	}
	return result
}

func TestParseBplist_SimpleDict(t *testing.T) {
	// {"name": "alice"}
	objects := [][]byte{
		bplistDict([]int{1}, []int{2}), // obj 0: dict
		bplistString("name"),            // obj 1: key
		bplistString("alice"),           // obj 2: value
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'm' {
		t.Fatalf("expected dict, got %c", val.kind)
	}
	if v, ok := val.dictVal["name"]; !ok || v.strVal != "alice" {
		t.Errorf("expected name=alice, got %+v", val.dictVal)
	}
}

func TestParseBplist_NestedDict(t *testing.T) {
	// {"outer": {"inner": "value"}}
	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),    // obj 0: outer dict
		bplistString("outer"),              // obj 1: key
		bplistDict([]int{3}, []int{4}),     // obj 2: inner dict
		bplistString("inner"),              // obj 3: inner key
		bplistString("value"),              // obj 4: inner value
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	outer, ok := val.dictVal["outer"]
	if !ok || outer.kind != 'm' {
		t.Fatalf("expected nested dict")
	}
	inner, ok := outer.dictVal["inner"]
	if !ok || inner.strVal != "value" {
		t.Errorf("expected inner=value, got %+v", outer.dictVal)
	}
}

func TestParseBplist_Array(t *testing.T) {
	// ["a", "b", "c"]
	objects := [][]byte{
		bplistArray(1, 2, 3),  // obj 0: array
		bplistString("a"),     // obj 1
		bplistString("b"),     // obj 2
		bplistString("c"),     // obj 3
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'a' {
		t.Fatalf("expected array, got %c", val.kind)
	}
	if len(val.arrayVal) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(val.arrayVal))
	}
	if val.arrayVal[0].strVal != "a" || val.arrayVal[2].strVal != "c" {
		t.Errorf("unexpected array values: %v", val.arrayVal)
	}
}

func TestParseBplist_DataValue(t *testing.T) {
	// {"blob": <deadbeef>}
	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("blob"),
		bplistData([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	blob, ok := val.dictVal["blob"]
	if !ok || blob.kind != 'd' {
		t.Fatalf("expected data value")
	}
	if len(blob.dataVal) != 4 || blob.dataVal[0] != 0xDE {
		t.Errorf("unexpected data: %x", blob.dataVal)
	}
}

func TestParseBplist_Integer(t *testing.T) {
	// {"count": 42}
	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("count"),
		bplistInt(42),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	count, ok := val.dictVal["count"]
	if !ok || count.kind != 'i' || count.intVal != 42 {
		t.Errorf("expected count=42, got %+v", count)
	}
}

func TestParseBplist_Bool(t *testing.T) {
	// {"flag": true, "off": false}
	objects := [][]byte{
		bplistDict([]int{1, 2}, []int{3, 4}),
		bplistString("flag"),
		bplistString("off"),
		bplistBool(true),
		bplistBool(false),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if f, ok := val.dictVal["flag"]; !ok || !f.boolVal {
		t.Errorf("expected flag=true")
	}
	if o, ok := val.dictVal["off"]; !ok || o.boolVal {
		t.Errorf("expected off=false")
	}
}

func TestParseBplist_Float(t *testing.T) {
	// float64 value
	floatBytes := make([]byte, 9)
	floatBytes[0] = 0x23 // real, 2^3 = 8 bytes
	binary.BigEndian.PutUint64(floatBytes[1:], math.Float64bits(3.14))

	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("pi"),
		floatBytes,
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	pi, ok := val.dictVal["pi"]
	if !ok || pi.kind != 'f' {
		t.Fatalf("expected float value")
	}
	if math.Abs(pi.floatVal-3.14) > 0.001 {
		t.Errorf("expected ~3.14, got %f", pi.floatVal)
	}
}

func TestParseBplist_Null(t *testing.T) {
	objects := [][]byte{
		bplistNull(),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'n' {
		t.Errorf("expected null, got %c", val.kind)
	}
}

func TestParseBplist_EmptyDict(t *testing.T) {
	objects := [][]byte{
		bplistDict(nil, nil),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'm' || len(val.dictVal) != 0 {
		t.Errorf("expected empty dict, got %+v", val)
	}
}

func TestParseBplist_EmptyArray(t *testing.T) {
	objects := [][]byte{
		bplistArray(),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'a' || len(val.arrayVal) != 0 {
		t.Errorf("expected empty array, got %+v", val)
	}
}

func TestParseBplist_LargeString(t *testing.T) {
	// String longer than 14 chars (triggers extended size)
	longStr := "this is a string that is longer than fourteen characters"
	objects := [][]byte{
		bplistString(longStr),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 's' || val.strVal != longStr {
		t.Errorf("expected %q, got %q", longStr, val.strVal)
	}
}

func TestParseBplist_LargeData(t *testing.T) {
	// Data longer than 14 bytes
	bigData := make([]byte, 128)
	for i := range bigData {
		bigData[i] = byte(i)
	}
	objects := [][]byte{
		bplistData(bigData),
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'd' || len(val.dataVal) != 128 {
		t.Errorf("expected 128 bytes of data, got %d", len(val.dataVal))
	}
	if val.dataVal[0] != 0 || val.dataVal[127] != 127 {
		t.Errorf("data content mismatch")
	}
}

func TestParseBplist_InvalidMagic(t *testing.T) {
	_, err := parseBplist([]byte("not a plist at all, this is just random text padding"))
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestParseBplist_TooShort(t *testing.T) {
	_, err := parseBplist([]byte("bplist00"))
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestParseBplist_UnicodeString(t *testing.T) {
	// Unicode string "café" (UTF-16BE)
	chars := []uint16{0x0063, 0x0061, 0x0066, 0x00E9} // c, a, f, é
	uniBytes := make([]byte, 1+len(chars)*2)
	uniBytes[0] = 0x60 | byte(len(chars)) // unicode string marker + count
	for i, c := range chars {
		binary.BigEndian.PutUint16(uniBytes[1+i*2:], c)
	}

	objects := [][]byte{uniBytes}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 's' || val.strVal != "café" {
		t.Errorf("expected 'café', got %q", val.strVal)
	}
}

// --- Hashdump-specific tests ---

func TestIsSystemAccount(t *testing.T) {
	tests := []struct {
		name     string
		isSystem bool
	}{
		{"root", false},
		{"_spotlight", true},
		{"_www", true},
		{"nobody", true},
		{"daemon", true},
		{"gary", false},
		{"admin", false},
		{"_sshd", true},
	}
	for _, tt := range tests {
		if got := isSystemAccount(tt.name); got != tt.isSystem {
			t.Errorf("isSystemAccount(%q) = %v, want %v", tt.name, got, tt.isSystem)
		}
	}
}

func TestFormatDarwinHash_PBKDF2(t *testing.T) {
	e := darwinHashEntry{
		HashType:   "SALTED-SHA512-PBKDF2",
		Iterations: 38000,
		Salt:       "aabbccdd",
		Entropy:    "deadbeef01020304",
	}
	got := formatDarwinHash(e)
	want := "$ml$38000$aabbccdd$deadbeef01020304"
	if got != want {
		t.Errorf("formatDarwinHash = %q, want %q", got, want)
	}
}

func TestFormatDarwinHash_SHA512(t *testing.T) {
	e := darwinHashEntry{
		HashType: "SALTED-SHA512",
		Salt:     "aabb",
		Entropy:  "ccdd",
	}
	got := formatDarwinHash(e)
	want := "$LION$aabbccdd"
	if got != want {
		t.Errorf("formatDarwinHash = %q, want %q", got, want)
	}
}

func TestBplistFirstString(t *testing.T) {
	// Direct string
	s := bplistValue{kind: 's', strVal: "hello"}
	if got := bplistFirstString(s); got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}

	// Integer
	i := bplistValue{kind: 'i', intVal: 501}
	if got := bplistFirstString(i); got != "501" {
		t.Errorf("expected '501', got %q", got)
	}

	// Array of strings
	a := bplistValue{kind: 'a', arrayVal: []bplistValue{
		{kind: 's', strVal: "first"},
		{kind: 's', strVal: "second"},
	}}
	if got := bplistFirstString(a); got != "first" {
		t.Errorf("expected 'first', got %q", got)
	}

	// Empty array
	empty := bplistValue{kind: 'a', arrayVal: nil}
	if got := bplistFirstString(empty); got != "" {
		t.Errorf("expected '', got %q", got)
	}
}

// TestParseShadowHashData tests the inner plist parsing for PBKDF2 hashes.
func TestParseShadowHashData(t *testing.T) {
	// Build a binary plist representing the inner ShadowHashData structure:
	// {"SALTED-SHA512-PBKDF2": {"iterations": 38000, "salt": <32 bytes>, "entropy": <128 bytes>}}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	entropy := make([]byte, 128)
	for i := range entropy {
		entropy[i] = byte(i + 0x80)
	}

	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),                     // obj 0: root dict
		bplistString("SALTED-SHA512-PBKDF2"),               // obj 1: key
		bplistDict([]int{3, 4, 5}, []int{6, 7, 8}),        // obj 2: hash dict
		bplistString("iterations"),                          // obj 3
		bplistString("salt"),                                // obj 4
		bplistString("entropy"),                             // obj 5
		bplistInt(38000),                                    // obj 6
		bplistData(salt),                                    // obj 7
		bplistData(entropy),                                 // obj 8
	}
	blob := buildBplist(objects, 0)

	entry := &darwinHashEntry{Username: "testuser"}
	result, err := parseShadowHashData(entry, blob)
	if err != nil {
		t.Fatalf("parseShadowHashData: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.HashType != "SALTED-SHA512-PBKDF2" {
		t.Errorf("HashType = %q, want SALTED-SHA512-PBKDF2", result.HashType)
	}
	if result.Iterations != 38000 {
		t.Errorf("Iterations = %d, want 38000", result.Iterations)
	}
	if len(result.Salt) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Salt length = %d hex chars, want 64", len(result.Salt))
	}
	if len(result.Entropy) != 256 { // 128 bytes = 256 hex chars
		t.Errorf("Entropy length = %d hex chars, want 256", len(result.Entropy))
	}
}

func TestParseShadowHashData_SRP(t *testing.T) {
	salt := []byte{0xAA, 0xBB}
	entropy := []byte{0xCC, 0xDD}

	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("SRP-RFC5054-4096-SHA512-PBKDF2"),
		bplistDict([]int{3, 4, 5}, []int{6, 7, 8}),
		bplistString("iterations"),
		bplistString("salt"),
		bplistString("entropy"),
		bplistInt(4096),
		bplistData(salt),
		bplistData(entropy),
	}
	blob := buildBplist(objects, 0)

	entry := &darwinHashEntry{Username: "testuser"}
	result, err := parseShadowHashData(entry, blob)
	if err != nil {
		t.Fatalf("parseShadowHashData: %v", err)
	}
	if result.HashType != "SRP-RFC5054-4096-SHA512-PBKDF2" {
		t.Errorf("HashType = %q", result.HashType)
	}
	if result.Iterations != 4096 {
		t.Errorf("Iterations = %d", result.Iterations)
	}
}

func TestParseDarwinUserPlist(t *testing.T) {
	// Build a synthetic user plist with ShadowHashData
	salt := make([]byte, 32)
	entropy := make([]byte, 128)

	// Inner plist (ShadowHashData blob)
	innerObjects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("SALTED-SHA512-PBKDF2"),
		bplistDict([]int{3, 4, 5}, []int{6, 7, 8}),
		bplistString("iterations"),
		bplistString("salt"),
		bplistString("entropy"),
		bplistInt(50000),
		bplistData(salt),
		bplistData(entropy),
	}
	innerBlob := buildBplist(innerObjects, 0)

	// Outer plist (user.plist)
	outerObjects := [][]byte{
		bplistDict([]int{1, 2, 3, 4, 5}, []int{6, 7, 8, 9, 10}), // obj 0: root
		bplistString("name"),                                       // obj 1
		bplistString("uid"),                                        // obj 2
		bplistString("home"),                                       // obj 3
		bplistString("shell"),                                      // obj 4
		bplistString("ShadowHashData"),                             // obj 5
		bplistArray(11),                                             // obj 6: name array
		bplistArray(12),                                             // obj 7: uid array
		bplistArray(13),                                             // obj 8: home array
		bplistArray(14),                                             // obj 9: shell array
		bplistArray(15),                                             // obj 10: ShadowHashData array
		bplistString("gary"),                                       // obj 11
		bplistString("501"),                                        // obj 12
		bplistString("/Users/gary"),                                // obj 13
		bplistString("/bin/zsh"),                                   // obj 14
		bplistData(innerBlob),                                      // obj 15: inner plist blob
	}
	outerData := buildBplist(outerObjects, 0)

	result, err := parseDarwinUserPlist("gary", outerData)
	if err != nil {
		t.Fatalf("parseDarwinUserPlist: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Username != "gary" {
		t.Errorf("Username = %q", result.Username)
	}
	if result.UID != "501" {
		t.Errorf("UID = %q", result.UID)
	}
	if result.Home != "/Users/gary" {
		t.Errorf("Home = %q", result.Home)
	}
	if result.Shell != "/bin/zsh" {
		t.Errorf("Shell = %q", result.Shell)
	}
	if result.HashType != "SALTED-SHA512-PBKDF2" {
		t.Errorf("HashType = %q", result.HashType)
	}
	if result.Iterations != 50000 {
		t.Errorf("Iterations = %d", result.Iterations)
	}
}

func TestParseDarwinUserPlist_NoShadowHash(t *testing.T) {
	// User plist without ShadowHashData (e.g., system user)
	objects := [][]byte{
		bplistDict([]int{1}, []int{2}),
		bplistString("name"),
		bplistArray(3),
		bplistString("nobody"),
	}
	data := buildBplist(objects, 0)

	result, err := parseDarwinUserPlist("nobody", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for user without ShadowHashData, got %+v", result)
	}
}

// --- Tests for bplist parser helper functions (Session 202) ---

func TestReadBEInt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int64
	}{
		{"1 byte zero", []byte{0x00}, 0},
		{"1 byte max", []byte{0xFF}, 255},
		{"1 byte mid", []byte{0x42}, 66},
		{"2 bytes zero", []byte{0x00, 0x00}, 0},
		{"2 bytes one", []byte{0x00, 0x01}, 1},
		{"2 bytes 256", []byte{0x01, 0x00}, 256},
		{"2 bytes max", []byte{0xFF, 0xFF}, 65535},
		{"4 bytes zero", []byte{0x00, 0x00, 0x00, 0x00}, 0},
		{"4 bytes one", []byte{0x00, 0x00, 0x00, 0x01}, 1},
		{"4 bytes max positive", []byte{0x7F, 0xFF, 0xFF, 0xFF}, 2147483647},
		{"4 bytes negative", []byte{0xFF, 0xFF, 0xFF, 0xFF}, -1},        // int32 -1
		{"4 bytes min negative", []byte{0x80, 0x00, 0x00, 0x00}, -2147483648}, // int32 min
		{"8 bytes zero", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},
		{"8 bytes one", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 1},
		{"8 bytes large", []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, 4294967296},
		// Non-standard sizes (3, 5, 6, 7 bytes) use default path
		{"3 bytes", []byte{0x01, 0x02, 0x03}, 0x010203},
		{"5 bytes", []byte{0x00, 0x00, 0x01, 0x00, 0x00}, 65536},
		{"empty", []byte{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readBEInt(tt.data)
			if got != tt.want {
				t.Errorf("readBEInt(%v) = %d, want %d", tt.data, got, tt.want)
			}
		})
	}
}

func TestReadSizedInt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", []byte{}, 0},
		{"1 byte", []byte{0x42}, 0x42},
		{"2 bytes", []byte{0x01, 0x00}, 0x0100},
		{"3 bytes", []byte{0x01, 0x02, 0x03}, 0x010203},
		{"4 bytes", []byte{0x00, 0x01, 0x00, 0x00}, 0x00010000},
		{"single zero", []byte{0x00}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readSizedInt(nil, tt.data)
			if got != tt.want {
				t.Errorf("readSizedInt(nil, %v) = %d (0x%X), want %d (0x%X)",
					tt.data, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestReadSizeAndStart(t *testing.T) {
	// readSizeAndStart operates on a bplistContext and reads size info from offset
	tests := []struct {
		name    string
		data    []byte
		offset  int
		objInfo int
		wantSz  int
		wantSt  int
		wantErr bool
	}{
		{
			name:    "non-extended size",
			data:    []byte{0x00},
			offset:  0,
			objInfo: 5,
			wantSz:  5,
			wantSt:  1,
		},
		{
			name:    "zero size non-extended",
			data:    []byte{0x00},
			offset:  0,
			objInfo: 0,
			wantSz:  0,
			wantSt:  1,
		},
		{
			name:    "max non-extended size",
			data:    []byte{0x00},
			offset:  0,
			objInfo: 14, // 0x0E — anything < 0x0F is non-extended
			wantSz:  14,
			wantSt:  1,
		},
		{
			name:    "extended size 1 byte",
			data:    []byte{0x00, 0x10, 0x20}, // marker=0x10 (int, 1 byte), value=0x20
			offset:  0,
			objInfo: 0x0F,
			wantSz:  0x20,
			wantSt:  3,
		},
		{
			name:    "extended size truncated",
			data:    []byte{0x00},
			offset:  0,
			objInfo: 0x0F,
			wantErr: true,
		},
		{
			name:    "extended size bad marker",
			data:    []byte{0x00, 0x50, 0x20}, // marker 0x50 is not an int marker (>>4 != 1)
			offset:  0,
			objInfo: 0x0F,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &bplistContext{data: tt.data}
			sz, st, err := ctx.readSizeAndStart(tt.offset, tt.objInfo)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sz != tt.wantSz {
				t.Errorf("size = %d, want %d", sz, tt.wantSz)
			}
			if st != tt.wantSt {
				t.Errorf("start = %d, want %d", st, tt.wantSt)
			}
		})
	}
}

// --- parseObject edge cases ---

func TestParseBplist_UnsupportedType(t *testing.T) {
	// UID type marker (0x80) — should be treated as null
	objects := [][]byte{
		{0x80}, // obj 0: UID type (unsupported → null)
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'n' {
		t.Errorf("expected null ('n') for unsupported type, got '%c'", val.kind)
	}
}

func TestParseBplist_DateType(t *testing.T) {
	// Date type marker (0x33) — unsupported, returns null
	objects := [][]byte{
		append([]byte{0x33}, make([]byte, 8)...), // 8 bytes of date data
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'n' {
		t.Errorf("expected null ('n') for date type, got '%c'", val.kind)
	}
}

func TestParseBplist_NonStringDictKey(t *testing.T) {
	// Dict with integer key — should be skipped (only string keys kept)
	// obj 0: dict with key=1 (int), value=2 (string); key=3 (string), value=4 (string)
	objects := [][]byte{
		bplistDict([]int{1, 3}, []int{2, 4}), // obj 0: dict
		bplistInt(99),                         // obj 1: integer key (not string)
		bplistString("skipped"),               // obj 2: value for int key
		bplistString("realkey"),               // obj 3: string key
		bplistString("realval"),               // obj 4: value for string key
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'm' {
		t.Fatalf("expected dict, got '%c'", val.kind)
	}
	// Integer key should be skipped, only string key kept
	if len(val.dictVal) != 1 {
		t.Errorf("expected 1 dict entry (non-string key skipped), got %d", len(val.dictVal))
	}
	if v, ok := val.dictVal["realkey"]; !ok || v.strVal != "realval" {
		t.Errorf("expected realkey=realval, got %+v", val.dictVal)
	}
}

func bplistFloat32(v float32) []byte {
	b := make([]byte, 5)
	b[0] = 0x22 // real, 4 bytes (1 << 2)
	binary.BigEndian.PutUint32(b[1:], math.Float32bits(v))
	return b
}

func bplistFloat64(v float64) []byte {
	b := make([]byte, 9)
	b[0] = 0x23 // real, 8 bytes (1 << 3)
	binary.BigEndian.PutUint64(b[1:], math.Float64bits(v))
	return b
}

func TestParseBplist_UnsupportedRealSize(t *testing.T) {
	// Real with objInfo=0 → 1 byte (1 << 0), not 4 or 8 → error
	objects := [][]byte{
		{0x20, 0x42}, // real marker 0x20 means 1-byte real (unsupported)
	}
	data := buildBplist(objects, 0)

	_, err := parseBplist(data)
	if err == nil {
		t.Error("expected error for unsupported real size (1 byte)")
	}
}

func TestParseBplist_ObjectIndexOutOfRange(t *testing.T) {
	// Array referencing object index 99 when only 2 objects exist
	objects := [][]byte{
		{0xA1, 99}, // array of 1 element, ref=99
		bplistString("unused"),
	}
	data := buildBplist(objects, 0)

	_, err := parseBplist(data)
	if err == nil {
		t.Error("expected error for out-of-range object reference")
	}
}

func TestParseBplist_FillMarker(t *testing.T) {
	// Fill byte (0x0F) — should return null (default case in 0x0 switch)
	objects := [][]byte{
		{0x0F}, // fill marker
	}
	data := buildBplist(objects, 0)

	val, err := parseBplist(data)
	if err != nil {
		t.Fatalf("parseBplist: %v", err)
	}
	if val.kind != 'n' {
		t.Errorf("expected null for fill marker, got '%c'", val.kind)
	}
}

func TestReadBEInt_SignedBehavior(t *testing.T) {
	// 4-byte values should be sign-extended (int32 -> int64)
	// 2-byte values should NOT be sign-extended (uint16)
	tests := []struct {
		name string
		data []byte
		want int64
	}{
		{"2 bytes 0x8000 = 32768 (unsigned)", []byte{0x80, 0x00}, 32768},
		{"4 bytes 0x80000000 = -2147483648 (signed)", []byte{0x80, 0x00, 0x00, 0x00}, -2147483648},
		{"4 bytes 0xFFFFFFFE = -2 (signed)", []byte{0xFF, 0xFF, 0xFF, 0xFE}, -2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readBEInt(tt.data)
			if got != tt.want {
				t.Errorf("readBEInt(%v) = %d, want %d", tt.data, got, tt.want)
			}
		})
	}
}
