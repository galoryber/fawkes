package commands

import (
	"encoding/binary"
	"testing"
	"time"
)

// --- filetimeToTime tests ---

func TestFiletimeToTimeUnixEpoch(t *testing.T) {
	// Unix epoch: January 1, 1970 00:00:00 UTC
	// FILETIME = 11644473600 * 10000000 = 116444736000000000
	ft := int64(116444736000000000)
	result := filetimeToTime(ft)
	expected := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !result.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestFiletimeToTimeKnownDate(t *testing.T) {
	// January 1, 2025 00:00:00 UTC
	// Unix: 1735689600
	// FILETIME = (1735689600 + 11644473600) * 10000000 = 133801632000000000
	ft := int64(133801632000000000)
	result := filetimeToTime(ft)
	expected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if !result.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestFiletimeToTimeZero(t *testing.T) {
	// FILETIME 0 should produce a date before Unix epoch
	result := filetimeToTime(0)
	if result.Year() >= 1970 {
		t.Errorf("expected date before 1970, got %v", result)
	}
}

func TestFiletimeToTimeWindowsEpoch(t *testing.T) {
	// FILETIME 0 = January 1, 1601 00:00:00 UTC
	// filetimeToTime(0) = Unix(-11644473600, 0) = 1601-01-01
	result := filetimeToTime(0)
	expected := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	if !result.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// --- decodeUTF16 tests ---

func TestDecodeUTF16Simple(t *testing.T) {
	// "ABC" in UTF-16LE: 0x41,0x00, 0x42,0x00, 0x43,0x00
	data := []byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00}
	result := decodeUTF16(data)
	if result != "ABC" {
		t.Errorf("expected 'ABC', got '%s'", result)
	}
}

func TestDecodeUTF16WithNull(t *testing.T) {
	// "AB\0CD" — should stop at null
	data := []byte{0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0x43, 0x00, 0x44, 0x00}
	result := decodeUTF16(data)
	if result != "AB" {
		t.Errorf("expected 'AB', got '%s'", result)
	}
}

func TestDecodeUTF16Empty(t *testing.T) {
	result := decodeUTF16([]byte{})
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestDecodeUTF16SingleByte(t *testing.T) {
	result := decodeUTF16([]byte{0x41})
	if result != "" {
		t.Errorf("expected empty string for single byte, got '%s'", result)
	}
}

func TestDecodeUTF16NullTerminated(t *testing.T) {
	// "Hi\0\0\0" — padded with nulls (common in fixed-width fields)
	data := []byte{0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := decodeUTF16(data)
	if result != "Hi" {
		t.Errorf("expected 'Hi', got '%s'", result)
	}
}

func TestDecodeUTF16WindowsPath(t *testing.T) {
	// C:\Windows\System32
	path := `C:\Windows\System32`
	data := encodeUTF16LE(path)
	result := decodeUTF16(data)
	if result != path {
		t.Errorf("expected '%s', got '%s'", path, result)
	}
}

// --- usnReasonString tests ---

func TestUsnReasonStringCreate(t *testing.T) {
	result := usnReasonString(usnReasonFileCreate)
	if result != "Create" {
		t.Errorf("expected 'Create', got '%s'", result)
	}
}

func TestUsnReasonStringDelete(t *testing.T) {
	result := usnReasonString(usnReasonFileDelete)
	if result != "Delete" {
		t.Errorf("expected 'Delete', got '%s'", result)
	}
}

func TestUsnReasonStringDataChange(t *testing.T) {
	result := usnReasonString(usnReasonDataOverwrite)
	if result != "DataChange" {
		t.Errorf("expected 'DataChange', got '%s'", result)
	}
}

func TestUsnReasonStringRename(t *testing.T) {
	result := usnReasonString(usnReasonRenameOldName | usnReasonRenameNewName)
	if result != "Rename" {
		t.Errorf("expected 'Rename', got '%s'", result)
	}
}

func TestUsnReasonStringMultipleFlags(t *testing.T) {
	reason := uint32(usnReasonFileCreate | usnReasonDataOverwrite | usnReasonClose)
	result := usnReasonString(reason)
	expected := "Create|DataChange|Close"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestUsnReasonStringUnknown(t *testing.T) {
	// Named data flags only — not matched by any named category
	result := usnReasonString(usnReasonNamedDataOverwrite)
	if result != "0x00000010" {
		t.Errorf("expected hex fallback, got '%s'", result)
	}
}

func TestUsnReasonStringZero(t *testing.T) {
	result := usnReasonString(0)
	if result != "0x00000000" {
		t.Errorf("expected '0x00000000', got '%s'", result)
	}
}

func TestUsnReasonStringClose(t *testing.T) {
	result := usnReasonString(usnReasonClose)
	if result != "Close" {
		t.Errorf("expected 'Close', got '%s'", result)
	}
}

func TestUsnReasonStringSecurityAndInfo(t *testing.T) {
	reason := uint32(usnReasonSecurityChange | usnReasonBasicInfoChange)
	result := usnReasonString(reason)
	expected := "SecurityChange|InfoChange"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestUsnReasonStringAllFlags(t *testing.T) {
	reason := uint32(usnReasonFileCreate | usnReasonFileDelete | usnReasonDataOverwrite |
		usnReasonRenameOldName | usnReasonSecurityChange | usnReasonBasicInfoChange | usnReasonClose)
	result := usnReasonString(reason)
	expected := "Create|Delete|DataChange|Rename|SecurityChange|InfoChange|Close"
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

// --- parseShimcacheWin10 tests ---

// buildWin10ShimcacheData constructs a valid Win10 shimcache binary blob.
func buildWin10ShimcacheData(headerSize uint32, entries []shimTestEntry) []byte {
	// Header
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:4], headerSize)

	data := make([]byte, len(header))
	copy(data, header)

	for _, e := range entries {
		entry := buildWin10Entry(e.path, e.filetime)
		data = append(data, entry...)
	}
	return data
}

type shimTestEntry struct {
	path     string
	filetime uint64
}

// buildWin10Entry constructs a single Win10 shimcache entry.
// Format: sig(4) + unknown(4) + data_size(4) + [path_len(2) + path(UTF-16LE) + FILETIME(8)]
func buildWin10Entry(path string, filetime uint64) []byte {
	pathBytes := encodeUTF16LE(path)
	// data block: path_len(2) + path + FILETIME(8)
	dataSize := 2 + len(pathBytes) + 8
	entrySize := 12 + dataSize // sig + unknown + data_size + data

	buf := make([]byte, entrySize)
	binary.LittleEndian.PutUint32(buf[0:4], shimcacheWin10Sig)   // sig
	binary.LittleEndian.PutUint32(buf[4:8], 0)                   // unknown
	binary.LittleEndian.PutUint32(buf[8:12], uint32(dataSize))   // data_size
	binary.LittleEndian.PutUint16(buf[12:14], uint16(len(pathBytes))) // path_len
	copy(buf[14:14+len(pathBytes)], pathBytes)
	binary.LittleEndian.PutUint64(buf[14+len(pathBytes):], filetime)

	return buf
}

// encodeUTF16LE encodes a string as UTF-16LE bytes (no null terminator).
func encodeUTF16LE(s string) []byte {
	var result []byte
	for _, r := range s {
		if r < 0x10000 {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(r))
			result = append(result, b...)
		}
	}
	return result
}

func TestParseShimcacheWin10Empty(t *testing.T) {
	data := buildWin10ShimcacheData(52, nil)
	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseShimcacheWin10SingleEntry(t *testing.T) {
	// January 1, 2025 = FILETIME 133801632000000000
	ft := uint64(133801632000000000)
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\Windows\notepad.exe`, filetime: ft},
	})

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Path != `C:\Windows\notepad.exe` {
		t.Errorf("expected 'C:\\Windows\\notepad.exe', got '%s'", entries[0].Path)
	}
	if entries[0].LastModified.Year() != 2025 {
		t.Errorf("expected year 2025, got %d", entries[0].LastModified.Year())
	}
}

func TestParseShimcacheWin10MultipleEntries(t *testing.T) {
	ft1 := uint64(133801632000000000) // 2025-01-01
	ft2 := uint64(132516480000000000) // ~2021-01-01
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\Windows\notepad.exe`, filetime: ft1},
		{path: `C:\Windows\calc.exe`, filetime: ft2},
		{path: `C:\Program Files\app.exe`, filetime: 0},
	})

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[1].Path != `C:\Windows\calc.exe` {
		t.Errorf("entry[1] path: expected 'C:\\Windows\\calc.exe', got '%s'", entries[1].Path)
	}
	// Entry with filetime 0 should have zero time
	if !entries[2].LastModified.IsZero() {
		t.Errorf("entry[2] with filetime=0 should have zero time, got %v", entries[2].LastModified)
	}
}

func TestParseShimcacheWin10TooSmall(t *testing.T) {
	data := make([]byte, 30)
	_, err := parseShimcacheWin10(data)
	if err == nil {
		t.Error("expected error for data too small")
	}
}

func TestParseShimcacheWin10BadHeaderSize(t *testing.T) {
	data := make([]byte, 200)
	binary.LittleEndian.PutUint32(data[0:4], 200) // header size > 128
	_, err := parseShimcacheWin10(data)
	if err == nil {
		t.Error("expected error for unexpected header size")
	}
}

func TestParseShimcacheWin10TruncatedEntry(t *testing.T) {
	// Build data with entry that points past end of data
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\test.exe`, filetime: 133801632000000000},
	})
	// Truncate in the middle of the entry
	data = data[:60]
	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should gracefully stop parsing, not crash
	if len(entries) > 1 {
		t.Errorf("expected 0-1 entries from truncated data, got %d", len(entries))
	}
}

func TestParseShimcacheWin10NoSignatureEntry(t *testing.T) {
	// Build valid data then corrupt the second entry's signature
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\first.exe`, filetime: 133801632000000000},
		{path: `C:\second.exe`, filetime: 133801632000000000},
	})
	// Find second entry start and corrupt its signature
	first := buildWin10Entry(`C:\first.exe`, 133801632000000000)
	secondStart := 52 + len(first)
	binary.LittleEndian.PutUint32(data[secondStart:secondStart+4], 0xDEADBEEF)

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (should stop at bad signature), got %d", len(entries))
	}
}

func TestParseShimcacheWin10EntryMetadata(t *testing.T) {
	ft := uint64(133801632000000000)
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\test.exe`, filetime: ft},
	})

	entries, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries[0].DataOffset != 52 {
		t.Errorf("expected DataOffset=52, got %d", entries[0].DataOffset)
	}
	if entries[0].EntrySize <= 0 {
		t.Errorf("expected positive EntrySize, got %d", entries[0].EntrySize)
	}
	if entries[0].DataSize <= 0 {
		t.Errorf("expected positive DataSize, got %d", entries[0].DataSize)
	}
}

// --- parseShimcacheWin8 tests ---

// buildWin8ShimcacheData constructs a valid Win8 shimcache binary blob.
func buildWin8ShimcacheData(entries []shimTestEntry) []byte {
	// Header: 128 bytes, first 4 bytes = 0x80
	header := make([]byte, 128)
	binary.LittleEndian.PutUint32(header[0:4], 0x80)

	data := make([]byte, 128)
	copy(data, header)

	for _, e := range entries {
		entry := buildWin8Entry(e.path, e.filetime)
		data = append(data, entry...)
	}
	return data
}

// buildWin8Entry constructs a single Win8 shimcache entry.
// Format: path_len_chars(4) + path(UTF-16LE) + FILETIME(8) + data_size(4) + data
func buildWin8Entry(path string, filetime uint64) []byte {
	pathBytes := encodeUTF16LE(path)
	pathLenChars := len(pathBytes) / 2

	// path_len_chars(4) + path + filetime(8) + data_size(4) + data(0)
	entrySize := 4 + len(pathBytes) + 8 + 4

	buf := make([]byte, entrySize)
	offset := 0
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(pathLenChars))
	offset += 4
	copy(buf[offset:offset+len(pathBytes)], pathBytes)
	offset += len(pathBytes)
	binary.LittleEndian.PutUint64(buf[offset:offset+8], filetime)
	offset += 8
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0) // data size = 0
	return buf
}

func TestParseShimcacheWin8Empty(t *testing.T) {
	data := buildWin8ShimcacheData(nil)
	entries, err := parseShimcacheWin8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseShimcacheWin8SingleEntry(t *testing.T) {
	ft := uint64(133801632000000000)
	data := buildWin8ShimcacheData([]shimTestEntry{
		{path: `C:\Windows\explorer.exe`, filetime: ft},
	})

	entries, err := parseShimcacheWin8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Path != `C:\Windows\explorer.exe` {
		t.Errorf("expected 'C:\\Windows\\explorer.exe', got '%s'", entries[0].Path)
	}
}

func TestParseShimcacheWin8MultipleEntries(t *testing.T) {
	ft := uint64(133801632000000000)
	data := buildWin8ShimcacheData([]shimTestEntry{
		{path: `C:\first.exe`, filetime: ft},
		{path: `C:\second.exe`, filetime: ft},
		{path: `C:\third.exe`, filetime: 0},
	})

	entries, err := parseShimcacheWin8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestParseShimcacheWin8TooSmall(t *testing.T) {
	data := make([]byte, 100)
	_, err := parseShimcacheWin8(data)
	if err == nil {
		t.Error("expected error for data too small")
	}
}

func TestParseShimcacheWin8ZeroFiletime(t *testing.T) {
	data := buildWin8ShimcacheData([]shimTestEntry{
		{path: `C:\test.exe`, filetime: 0},
	})
	entries, err := parseShimcacheWin8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].LastModified.IsZero() {
		t.Errorf("expected zero time for filetime=0, got %v", entries[0].LastModified)
	}
}

// --- parseShimcache (auto-detect) tests ---

func TestParseShimcacheDetectsWin10(t *testing.T) {
	data := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\test.exe`, filetime: 133801632000000000},
	})
	entries, version, err := parseShimcache(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "Windows 10/11" {
		t.Errorf("expected 'Windows 10/11', got '%s'", version)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseShimcacheDetectsWin8(t *testing.T) {
	data := buildWin8ShimcacheData([]shimTestEntry{
		{path: `C:\test.exe`, filetime: 133801632000000000},
	})
	entries, version, err := parseShimcache(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "Windows 8/8.1" {
		t.Errorf("expected 'Windows 8/8.1', got '%s'", version)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseShimcacheTooSmall(t *testing.T) {
	_, _, err := parseShimcache([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for data too small")
	}
}

func TestParseShimcacheUnsupportedFormat(t *testing.T) {
	// Data with header that doesn't match any known format
	data := make([]byte, 200)
	binary.LittleEndian.PutUint32(data[0:4], 0x12345678)
	_, _, err := parseShimcache(data)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// --- rebuildShimcacheWin10 tests ---

func TestRebuildShimcacheWin10KeepAll(t *testing.T) {
	original := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\first.exe`, filetime: 133801632000000000},
		{path: `C:\second.exe`, filetime: 133801632000000000},
	})
	entries, err := parseShimcacheWin10(original)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	rebuilt := rebuildShimcacheWin10(original[:52], entries, original)
	if rebuilt == nil {
		t.Fatal("rebuild returned nil")
	}

	// Should be identical to original
	if len(rebuilt) != len(original) {
		t.Errorf("expected len %d, got %d", len(original), len(rebuilt))
	}

	// Parse rebuilt data — should produce same entries
	reEntries, err := parseShimcacheWin10(rebuilt)
	if err != nil {
		t.Fatalf("parse rebuilt error: %v", err)
	}
	if len(reEntries) != len(entries) {
		t.Errorf("expected %d entries, got %d", len(entries), len(reEntries))
	}
}

func TestRebuildShimcacheWin10RemoveOne(t *testing.T) {
	original := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\keep.exe`, filetime: 133801632000000000},
		{path: `C:\remove.exe`, filetime: 133801632000000000},
		{path: `C:\alsokeep.exe`, filetime: 133801632000000000},
	})
	entries, err := parseShimcacheWin10(original)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Keep entries 0 and 2, remove entry 1
	keep := []shimcacheEntry{entries[0], entries[2]}
	rebuilt := rebuildShimcacheWin10(original[:52], keep, original)
	if rebuilt == nil {
		t.Fatal("rebuild returned nil")
	}

	reEntries, err := parseShimcacheWin10(rebuilt)
	if err != nil {
		t.Fatalf("parse rebuilt error: %v", err)
	}
	if len(reEntries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(reEntries))
	}
	if reEntries[0].Path != `C:\keep.exe` {
		t.Errorf("entry[0]: expected 'C:\\keep.exe', got '%s'", reEntries[0].Path)
	}
	if reEntries[1].Path != `C:\alsokeep.exe` {
		t.Errorf("entry[1]: expected 'C:\\alsokeep.exe', got '%s'", reEntries[1].Path)
	}
}

func TestRebuildShimcacheWin10Empty(t *testing.T) {
	original := buildWin10ShimcacheData(52, []shimTestEntry{
		{path: `C:\test.exe`, filetime: 133801632000000000},
	})

	rebuilt := rebuildShimcacheWin10(original[:52], nil, original)
	if rebuilt == nil {
		t.Fatal("rebuild returned nil")
	}
	if len(rebuilt) != 52 {
		t.Errorf("expected header-only (52 bytes), got %d", len(rebuilt))
	}

	// Parse rebuilt — should have 0 entries
	entries, err := parseShimcacheWin10(rebuilt)
	if err != nil {
		t.Fatalf("parse rebuilt error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestRebuildShimcacheWin10BadOffset(t *testing.T) {
	// Entry with DataOffset past end of original data
	header := make([]byte, 52)
	binary.LittleEndian.PutUint32(header[0:4], 52)
	entries := []shimcacheEntry{
		{DataOffset: 9999, EntrySize: 100},
	}
	rebuilt := rebuildShimcacheWin10(header, entries, make([]byte, 100))
	if rebuilt != nil {
		t.Error("expected nil for out-of-bounds offset")
	}
}

// --- shimcacheWin10Sig constant test ---

func TestShimcacheWin10SigValue(t *testing.T) {
	// "10ts" as little-endian uint32
	expected := []byte("10ts")
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, shimcacheWin10Sig)
	for i, b := range expected {
		if buf[i] != b {
			t.Errorf("byte %d: expected 0x%02X ('%c'), got 0x%02X", i, b, b, buf[i])
		}
	}
}

// --- Roundtrip tests ---

func TestShimcacheWin10Roundtrip(t *testing.T) {
	// Build → parse → verify for various path types
	paths := []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Program Files (x86)\App\app.exe`,
		`C:\Users\Administrator\Desktop\test.exe`,
		`\\server\share\remote.exe`,
	}
	var entries []shimTestEntry
	for _, p := range paths {
		entries = append(entries, shimTestEntry{path: p, filetime: 133801632000000000})
	}

	data := buildWin10ShimcacheData(52, entries)
	parsed, err := parseShimcacheWin10(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(parsed) != len(paths) {
		t.Fatalf("expected %d entries, got %d", len(paths), len(parsed))
	}
	for i, p := range paths {
		if parsed[i].Path != p {
			t.Errorf("entry[%d]: expected '%s', got '%s'", i, p, parsed[i].Path)
		}
	}
}

func TestShimcacheWin8Roundtrip(t *testing.T) {
	paths := []string{
		`C:\Windows\notepad.exe`,
		`C:\test\app.exe`,
	}
	var entries []shimTestEntry
	for _, p := range paths {
		entries = append(entries, shimTestEntry{path: p, filetime: 133801632000000000})
	}

	data := buildWin8ShimcacheData(entries)
	parsed, err := parseShimcacheWin8(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(parsed) != len(paths) {
		t.Fatalf("expected %d entries, got %d", len(paths), len(parsed))
	}
	for i, p := range paths {
		if parsed[i].Path != p {
			t.Errorf("entry[%d]: expected '%s', got '%s'", i, p, parsed[i].Path)
		}
	}
}
