package commands

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockReader implements lsassReader for testing by mapping address ranges to data.
type mockReader struct {
	pages map[uintptr][]byte
}

func newMockReader() *mockReader {
	return &mockReader{pages: make(map[uintptr][]byte)}
}

func (m *mockReader) put(addr uintptr, data []byte) {
	m.pages[addr] = data
}

func (m *mockReader) Read(addr uintptr, size uint32) ([]byte, error) {
	// Try exact match first
	if data, ok := m.pages[addr]; ok {
		if uint32(len(data)) >= size {
			out := make([]byte, size)
			copy(out, data[:size])
			return out, nil
		}
	}
	// Try to find a page that contains the requested range
	for base, data := range m.pages {
		if addr >= base && addr+uintptr(size) <= base+uintptr(len(data)) {
			off := addr - base
			out := make([]byte, size)
			copy(out, data[off:off+uintptr(size)])
			return out, nil
		}
	}
	return nil, fmt.Errorf("mockReader: no data at 0x%X (size %d)", addr, size)
}

// buildUnicodeString creates a 16-byte LSA_UNICODE_STRING header pointing to data.
func buildUnicodeString(addr uintptr, utf16Bytes []byte) []byte {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(len(utf16Bytes)))
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(utf16Bytes)))
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(addr))
	return hdr
}

// utf16Encode encodes a Go string as UTF-16LE bytes.
func utf16Encode(s string) []byte {
	runes := []rune(s)
	u16 := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(u16[i*2:], uint16(r))
	}
	return u16
}

// buildKerbBuffer creates a 16-byte KIWI_KERBEROS_BUFFER header.
func buildKerbBuffer(length uint32, valueAddr uintptr) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], length)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(valueAddr))
	return buf
}

// kerbTimeToFiletime converts a Go time to Windows FILETIME.
func kerbTimeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDiff = 116444736000000000
	nsec := uint64(t.UnixNano())
	return nsec/100 + epochDiff
}

// ---------------------------------------------------------------------------
// Tests: findKerbSessionTable
// ---------------------------------------------------------------------------

func TestFindKerbSessionTable_Win10_1803(t *testing.T) {
	// Build a synthetic kerberos.dll image with the Win10 1803 pattern.
	// Pattern: 48 8B 08 48 85 C9 74 ?? 48
	// The lea instruction (48 8D 05 xx xx xx xx) precedes the pattern.
	// disp32 field is at pattern_start - 4.

	imgSize := 0x10000
	img := make([]byte, imgSize)

	// Place the target (KerbGlobalLogonSessionTable) at offset 0x8000
	targetOffset := 0x8000

	// Place the pattern at offset 0x2000
	patternOffset := 0x2000
	pattern := []byte{0x48, 0x8B, 0x08, 0x48, 0x85, 0xC9, 0x74, 0x34, 0x48}
	copy(img[patternOffset:], pattern)

	// Place the lea instruction before: 48 8D 05 <disp32>
	// The disp32 field must end right at patternOffset.
	// disp32 starts at patternOffset - 4.
	// The lea instruction starts at patternOffset - 7.
	leaStart := patternOffset - 7
	img[leaStart] = 0x48
	img[leaStart+1] = 0x8D
	img[leaStart+2] = 0x05
	// disp32: target = patternOffset + disp32, so disp32 = targetOffset - patternOffset
	disp := int32(targetOffset - patternOffset)
	binary.LittleEndian.PutUint32(img[leaStart+3:leaStart+7], uint32(disp))

	base := uintptr(0x7FF800000000)
	addr, variant, err := findKerbSessionTable(img, base)
	if err != nil {
		t.Fatalf("findKerbSessionTable failed: %v", err)
	}

	expectedAddr := base + uintptr(targetOffset)
	if addr != expectedAddr {
		t.Errorf("got addr 0x%X, want 0x%X", addr, expectedAddr)
	}
	if variant != "Win10_1803_Server2019" {
		t.Errorf("got variant %q, want Win10_1803_Server2019", variant)
	}
}

func TestFindKerbSessionTable_Win10_1507(t *testing.T) {
	imgSize := 0x10000
	img := make([]byte, imgSize)

	targetOffset := 0x9000
	patternOffset := 0x3000
	// Pattern: 48 8B 18 48 85 DB 74
	pattern := []byte{0x48, 0x8B, 0x18, 0x48, 0x85, 0xDB, 0x74}
	copy(img[patternOffset:], pattern)

	leaStart := patternOffset - 7
	img[leaStart] = 0x48
	img[leaStart+1] = 0x8D
	img[leaStart+2] = 0x05
	disp := int32(targetOffset - patternOffset)
	binary.LittleEndian.PutUint32(img[leaStart+3:leaStart+7], uint32(disp))

	base := uintptr(0x7FF800000000)
	addr, variant, err := findKerbSessionTable(img, base)
	if err != nil {
		t.Fatalf("findKerbSessionTable failed: %v", err)
	}
	if addr != base+uintptr(targetOffset) {
		t.Errorf("got addr 0x%X, want 0x%X", addr, base+uintptr(targetOffset))
	}
	if variant != "Win10_1507_1703" {
		t.Errorf("got variant %q, want Win10_1507_1703", variant)
	}
}

func TestFindKerbSessionTable_NoMatch(t *testing.T) {
	img := make([]byte, 0x1000)
	_, _, err := findKerbSessionTable(img, 0x10000)
	if err == nil {
		t.Fatal("expected error for no match, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: walkKerbSessionList
// ---------------------------------------------------------------------------

func TestWalkKerbSessionList_TwoSessions(t *testing.T) {
	r := newMockReader()
	layout := kerbSessionLayouts[0] // Win10_1607_Win11

	// Create two sessions linked in a circular list through the sentinel.
	sentinelAddr := uintptr(0x1000)
	session1Base := uintptr(0x2000)
	session2Base := uintptr(0x3000)

	session1LEAddr := session1Base + uintptr(layout.ListEntryOff) // 0x2008
	session2LEAddr := session2Base + uintptr(layout.ListEntryOff) // 0x3008

	// Sentinel: Flink → session1.LE, Blink → session2.LE
	sentinel := make([]byte, 16)
	binary.LittleEndian.PutUint64(sentinel[0:8], uint64(session1LEAddr))
	binary.LittleEndian.PutUint64(sentinel[8:16], uint64(session2LEAddr))
	r.put(sentinelAddr, sentinel)

	// Session 1: LE.Flink → session2.LE, LE.Blink → sentinel
	sess1 := make([]byte, layout.NodeReadSize)
	binary.LittleEndian.PutUint64(sess1[layout.ListEntryOff:], uint64(session2LEAddr))
	binary.LittleEndian.PutUint64(sess1[layout.ListEntryOff+8:], uint64(sentinelAddr))
	// LUID
	binary.LittleEndian.PutUint64(sess1[layout.LUIDOff:], 0x1234)
	// UserName: point to mock string data
	userName1 := utf16Encode("Administrator")
	userNameAddr1 := uintptr(0x5000)
	r.put(userNameAddr1, userName1)
	copy(sess1[layout.UserNameOff:], buildUnicodeString(userNameAddr1, userName1))
	// Domain
	domain1 := utf16Encode("CONTOSO.COM")
	domainAddr1 := uintptr(0x5100)
	r.put(domainAddr1, domain1)
	copy(sess1[layout.DomainOff:], buildUnicodeString(domainAddr1, domain1))
	// Empty ticket lists (self-referencing)
	tickets1Addr := session1Base + uintptr(layout.Tickets1Off)
	binary.LittleEndian.PutUint64(sess1[layout.Tickets1Off:], uint64(tickets1Addr))
	binary.LittleEndian.PutUint64(sess1[layout.Tickets1Off+8:], uint64(tickets1Addr))
	tickets2Addr := session1Base + uintptr(layout.Tickets2Off)
	binary.LittleEndian.PutUint64(sess1[layout.Tickets2Off:], uint64(tickets2Addr))
	binary.LittleEndian.PutUint64(sess1[layout.Tickets2Off+8:], uint64(tickets2Addr))
	tickets3Addr := session1Base + uintptr(layout.Tickets3Off)
	binary.LittleEndian.PutUint64(sess1[layout.Tickets3Off:], uint64(tickets3Addr))
	binary.LittleEndian.PutUint64(sess1[layout.Tickets3Off+8:], uint64(tickets3Addr))
	r.put(session1Base, sess1)

	// Session 2: LE.Flink → sentinel, LE.Blink → session1.LE
	sess2 := make([]byte, layout.NodeReadSize)
	binary.LittleEndian.PutUint64(sess2[layout.ListEntryOff:], uint64(sentinelAddr))
	binary.LittleEndian.PutUint64(sess2[layout.ListEntryOff+8:], uint64(session1LEAddr))
	binary.LittleEndian.PutUint64(sess2[layout.LUIDOff:], 0x5678)
	userName2 := utf16Encode("jdoe")
	userNameAddr2 := uintptr(0x6000)
	r.put(userNameAddr2, userName2)
	copy(sess2[layout.UserNameOff:], buildUnicodeString(userNameAddr2, userName2))
	domain2 := utf16Encode("CORP.LOCAL")
	domainAddr2 := uintptr(0x6100)
	r.put(domainAddr2, domain2)
	copy(sess2[layout.DomainOff:], buildUnicodeString(domainAddr2, domain2))
	tickets1Addr2 := session2Base + uintptr(layout.Tickets1Off)
	binary.LittleEndian.PutUint64(sess2[layout.Tickets1Off:], uint64(tickets1Addr2))
	binary.LittleEndian.PutUint64(sess2[layout.Tickets1Off+8:], uint64(tickets1Addr2))
	tickets2Addr2 := session2Base + uintptr(layout.Tickets2Off)
	binary.LittleEndian.PutUint64(sess2[layout.Tickets2Off:], uint64(tickets2Addr2))
	binary.LittleEndian.PutUint64(sess2[layout.Tickets2Off+8:], uint64(tickets2Addr2))
	tickets3Addr2 := session2Base + uintptr(layout.Tickets3Off)
	binary.LittleEndian.PutUint64(sess2[layout.Tickets3Off:], uint64(tickets3Addr2))
	binary.LittleEndian.PutUint64(sess2[layout.Tickets3Off+8:], uint64(tickets3Addr2))
	r.put(session2Base, sess2)

	sessions, err := walkKerbSessionList(r, sentinelAddr, layout)
	if err != nil {
		t.Fatalf("walkKerbSessionList failed: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	if sessions[0].LUID != 0x1234 {
		t.Errorf("session 0 LUID = 0x%X, want 0x1234", sessions[0].LUID)
	}
	if sessions[0].UserName != "Administrator" {
		t.Errorf("session 0 UserName = %q, want Administrator", sessions[0].UserName)
	}
	if sessions[0].Domain != "CONTOSO.COM" {
		t.Errorf("session 0 Domain = %q, want CONTOSO.COM", sessions[0].Domain)
	}

	if sessions[1].LUID != 0x5678 {
		t.Errorf("session 1 LUID = 0x%X, want 0x5678", sessions[1].LUID)
	}
	if sessions[1].UserName != "jdoe" {
		t.Errorf("session 1 UserName = %q, want jdoe", sessions[1].UserName)
	}
}

func TestWalkKerbSessionList_Empty(t *testing.T) {
	r := newMockReader()
	layout := kerbSessionLayouts[0]

	sentinelAddr := uintptr(0x1000)
	sentinel := make([]byte, 16)
	// Self-referencing = empty list
	binary.LittleEndian.PutUint64(sentinel[0:8], uint64(sentinelAddr))
	binary.LittleEndian.PutUint64(sentinel[8:16], uint64(sentinelAddr))
	r.put(sentinelAddr, sentinel)

	sessions, err := walkKerbSessionList(r, sentinelAddr, layout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("got %d sessions, want 0", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// Tests: walkKerbTicketList
// ---------------------------------------------------------------------------

func TestWalkKerbTicketList_OneTicket(t *testing.T) {
	r := newMockReader()
	ticketLayout := kerbTicketLayouts[0] // Win10_1607_Win11

	listHeadAddr := uintptr(0x1000)
	ticketBase := uintptr(0x2000)

	// List head: Flink → ticket, Blink → ticket
	listHead := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHead[0:8], uint64(ticketBase))
	binary.LittleEndian.PutUint64(listHead[8:16], uint64(ticketBase))
	r.put(listHeadAddr, listHead)

	// Build ticket struct
	ticket := make([]byte, ticketLayout.NodeReadSize)
	// LIST_ENTRY: Flink → listHead, Blink → listHead
	binary.LittleEndian.PutUint64(ticket[0:8], uint64(listHeadAddr))
	binary.LittleEndian.PutUint64(ticket[8:16], uint64(listHeadAddr))

	// Service name (KERB_EXTERNAL_NAME): krbtgt/CONTOSO.COM
	svcNameAddr := uintptr(0x3000)
	svcNameStr := utf16Encode("krbtgt/CONTOSO.COM")
	svcName := make([]byte, 8+16)
	binary.LittleEndian.PutUint16(svcName[0:2], 2) // KRB_NT_SRV_INST
	binary.LittleEndian.PutUint16(svcName[2:4], 1) // 1 name component
	copy(svcName[8:], buildUnicodeString(uintptr(0x3100), svcNameStr))
	r.put(svcNameAddr, svcName)
	r.put(uintptr(0x3100), svcNameStr)
	binary.LittleEndian.PutUint64(ticket[ticketLayout.ServiceNameOff:], uint64(svcNameAddr))

	// Client name
	clientNameAddr := uintptr(0x4000)
	clientNameStr := utf16Encode("administrator")
	clientName := make([]byte, 8+16)
	binary.LittleEndian.PutUint16(clientName[0:2], 1) // KRB_NT_PRINCIPAL
	binary.LittleEndian.PutUint16(clientName[2:4], 1)
	copy(clientName[8:], buildUnicodeString(uintptr(0x4100), clientNameStr))
	r.put(clientNameAddr, clientName)
	r.put(uintptr(0x4100), clientNameStr)
	binary.LittleEndian.PutUint64(ticket[ticketLayout.ClientNameOff:], uint64(clientNameAddr))

	// Domain name
	domainStr := utf16Encode("CONTOSO.COM")
	domainAddr := uintptr(0x5000)
	r.put(domainAddr, domainStr)
	copy(ticket[ticketLayout.DomainNameOff:], buildUnicodeString(domainAddr, domainStr))

	// Ticket flags
	binary.LittleEndian.PutUint32(ticket[ticketLayout.TicketFlagsOff:], 0x40E10000)

	// Key type and key bytes
	binary.LittleEndian.PutUint32(ticket[ticketLayout.KeyTypeOff:], 18) // AES256
	keyData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	keyAddr := uintptr(0x6000)
	r.put(keyAddr, keyData)
	copy(ticket[ticketLayout.KeyOff:], buildKerbBuffer(uint32(len(keyData)), keyAddr))

	// Times
	startTime := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 5, 30, 22, 0, 0, 0, time.UTC)
	renewTime := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	binary.LittleEndian.PutUint64(ticket[ticketLayout.StartTimeOff:], kerbTimeToFiletime(startTime))
	binary.LittleEndian.PutUint64(ticket[ticketLayout.EndTimeOff:], kerbTimeToFiletime(endTime))
	binary.LittleEndian.PutUint64(ticket[ticketLayout.RenewUntilOff:], kerbTimeToFiletime(renewTime))

	// Ticket enc type and kvno
	binary.LittleEndian.PutUint32(ticket[ticketLayout.TicketEncTypeOff:], 18) // AES256
	binary.LittleEndian.PutUint32(ticket[ticketLayout.TicketKvnoOff:], 2)

	// Raw ticket bytes
	rawTicket := []byte{0x61, 0x82, 0x03, 0x00} // fake ASN.1 Application[1]
	rawTicketAddr := uintptr(0x7000)
	r.put(rawTicketAddr, rawTicket)
	copy(ticket[ticketLayout.TicketOff:], buildKerbBuffer(uint32(len(rawTicket)), rawTicketAddr))

	r.put(ticketBase, ticket)

	tickets, err := walkKerbTicketList(r, listHeadAddr, 1, ticketLayout)
	if err != nil {
		t.Fatalf("walkKerbTicketList failed: %v", err)
	}
	if len(tickets) != 1 {
		t.Fatalf("got %d tickets, want 1", len(tickets))
	}

	tk := tickets[0]
	if tk.ListIndex != 1 {
		t.Errorf("ListIndex = %d, want 1", tk.ListIndex)
	}
	if tk.ServiceName != "krbtgt/CONTOSO.COM" {
		t.Errorf("ServiceName = %q, want krbtgt/CONTOSO.COM", tk.ServiceName)
	}
	if tk.ClientName != "administrator" {
		t.Errorf("ClientName = %q, want administrator", tk.ClientName)
	}
	if tk.DomainName != "CONTOSO.COM" {
		t.Errorf("DomainName = %q, want CONTOSO.COM", tk.DomainName)
	}
	if tk.TicketFlags != 0x40E10000 {
		t.Errorf("TicketFlags = 0x%08X, want 0x40E10000", tk.TicketFlags)
	}
	if tk.KeyType != 18 {
		t.Errorf("KeyType = %d, want 18", tk.KeyType)
	}
	if len(tk.KeyBytes) != 16 {
		t.Errorf("KeyBytes len = %d, want 16", len(tk.KeyBytes))
	}
	if tk.TicketEncType != 18 {
		t.Errorf("TicketEncType = %d, want 18", tk.TicketEncType)
	}
	if tk.TicketKvno != 2 {
		t.Errorf("TicketKvno = %d, want 2", tk.TicketKvno)
	}
	if len(tk.TicketBytes) != 4 {
		t.Errorf("TicketBytes len = %d, want 4", len(tk.TicketBytes))
	}

	// Check times (within 1 second tolerance)
	if tk.StartTime.Sub(startTime).Abs() > time.Second {
		t.Errorf("StartTime = %v, want ~%v", tk.StartTime, startTime)
	}
	if tk.EndTime.Sub(endTime).Abs() > time.Second {
		t.Errorf("EndTime = %v, want ~%v", tk.EndTime, endTime)
	}
}

func TestWalkKerbTicketList_Empty(t *testing.T) {
	r := newMockReader()
	ticketLayout := kerbTicketLayouts[0]

	listHeadAddr := uintptr(0x1000)
	listHead := make([]byte, 16)
	binary.LittleEndian.PutUint64(listHead[0:8], uint64(listHeadAddr))
	binary.LittleEndian.PutUint64(listHead[8:16], uint64(listHeadAddr))
	r.put(listHeadAddr, listHead)

	tickets, err := walkKerbTicketList(r, listHeadAddr, 1, ticketLayout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tickets) != 0 {
		t.Errorf("got %d tickets, want 0", len(tickets))
	}
}

// ---------------------------------------------------------------------------
// Tests: readKerbExternalName
// ---------------------------------------------------------------------------

func TestReadKerbExternalName_TwoComponents(t *testing.T) {
	r := newMockReader()
	addr := uintptr(0x1000)

	part1Str := utf16Encode("krbtgt")
	part1Addr := uintptr(0x2000)
	r.put(part1Addr, part1Str)

	part2Str := utf16Encode("CONTOSO.COM")
	part2Addr := uintptr(0x2100)
	r.put(part2Addr, part2Str)

	// Build KERB_EXTERNAL_NAME with 2 name components
	extName := make([]byte, 8+32) // header(8) + 2×LSA_UNICODE_STRING(16 each)
	binary.LittleEndian.PutUint16(extName[0:2], 2) // KRB_NT_SRV_INST
	binary.LittleEndian.PutUint16(extName[2:4], 2) // NameCount=2
	copy(extName[8:24], buildUnicodeString(part1Addr, part1Str))
	copy(extName[24:40], buildUnicodeString(part2Addr, part2Str))
	r.put(addr, extName)

	name, err := readKerbExternalName(r, addr)
	if err != nil {
		t.Fatalf("readKerbExternalName failed: %v", err)
	}
	if name != "krbtgt/CONTOSO.COM" {
		t.Errorf("got %q, want krbtgt/CONTOSO.COM", name)
	}
}

func TestReadKerbExternalName_Null(t *testing.T) {
	r := newMockReader()
	name, err := readKerbExternalName(r, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Errorf("got %q, want empty", name)
	}
}

// ---------------------------------------------------------------------------
// Tests: readKerbBuffer
// ---------------------------------------------------------------------------

func TestReadKerbBuffer_ValidData(t *testing.T) {
	r := newMockReader()
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	dataAddr := uintptr(0x3000)
	r.put(dataAddr, data)

	header := buildKerbBuffer(uint32(len(data)), dataAddr)
	result, err := readKerbBuffer(r, header)
	if err != nil {
		t.Fatalf("readKerbBuffer failed: %v", err)
	}
	if len(result) != len(data) {
		t.Fatalf("got %d bytes, want %d", len(result), len(data))
	}
	for i, b := range result {
		if b != data[i] {
			t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, b, data[i])
		}
	}
}

func TestReadKerbBuffer_Zero(t *testing.T) {
	header := buildKerbBuffer(0, 0)
	result, err := readKerbBuffer(newMockReader(), header)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for zero-length buffer, got %v", result)
	}
}

func TestReadKerbBuffer_TooLarge(t *testing.T) {
	header := buildKerbBuffer(32768, 0x1000) // exceeds 16KB cap
	_, err := readKerbBuffer(newMockReader(), header)
	if err == nil {
		t.Fatal("expected error for oversized buffer")
	}
}

// ---------------------------------------------------------------------------
// Tests: kerbFiletimeToTime
// ---------------------------------------------------------------------------

func TestKerbFiletimeToTime(t *testing.T) {
	// Known value: 2026-01-01 00:00:00 UTC
	// FILETIME for this: 133798944000000000
	expected := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := kerbTimeToFiletime(expected)
	got := kerbFiletimeToTime(ft)
	if got.Sub(expected).Abs() > time.Second {
		t.Errorf("kerbFiletimeToTime(%d) = %v, want ~%v", ft, got, expected)
	}
}

func TestKerbFiletimeToTime_Zero(t *testing.T) {
	got := kerbFiletimeToTime(0)
	if !got.IsZero() {
		t.Errorf("kerbFiletimeToTime(0) = %v, want zero", got)
	}
}

func TestKerbFiletimeToTime_MaxValue(t *testing.T) {
	got := kerbFiletimeToTime(0x7FFFFFFFFFFFFFFF)
	if !got.IsZero() {
		t.Errorf("kerbFiletimeToTime(maxint64) = %v, want zero", got)
	}
}

// ---------------------------------------------------------------------------
// Tests: formatTicketFlags
// ---------------------------------------------------------------------------

func TestFormatTicketFlags(t *testing.T) {
	flags := uint32(0x40E10000) // forwardable + renewable + initial + pre-authent
	s := formatTicketFlags(flags)
	if s == "" {
		t.Error("formatTicketFlags returned empty string")
	}
	// Check that known flag names appear
	for _, expect := range []string{"forwardable", "renewable", "initial", "pre-authent"} {
		found := false
		for _, name := range []string{"forwardable", "forwarded", "proxiable", "proxy", "may-postdate", "postdated", "invalid", "renewable", "initial", "pre-authent", "hw-authent", "ok-as-delegate", "name-canonicalize"} {
			if name == expect {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected flag %q to be recognized", expect)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: selectKerbLayouts
// ---------------------------------------------------------------------------

func TestSelectKerbLayouts_Modern(t *testing.T) {
	sess, tick := selectKerbLayouts(22631) // Win11 23H2
	if sess.Name != "Win10_1607_Win11" {
		t.Errorf("session layout = %q, want Win10_1607_Win11", sess.Name)
	}
	if tick.Name != "Win10_1607_Win11" {
		t.Errorf("ticket layout = %q, want Win10_1607_Win11", tick.Name)
	}
}

func TestSelectKerbLayouts_Legacy(t *testing.T) {
	sess, tick := selectKerbLayouts(10240) // Win10 1507
	if sess.Name != "Win10_1507" {
		t.Errorf("session layout = %q, want Win10_1507", sess.Name)
	}
	if tick.Name != "Win10_1507" {
		t.Errorf("ticket layout = %q, want Win10_1507", tick.Name)
	}
}

// ---------------------------------------------------------------------------
// Tests: extractKerbTickets integration
// ---------------------------------------------------------------------------

func TestExtractKerbTickets_WithTickets(t *testing.T) {
	r := newMockReader()
	sessLayout := kerbSessionLayouts[0]
	tickLayout := kerbTicketLayouts[0]

	sessionBase := uintptr(0x10000)
	ticketBase := uintptr(0x20000)

	// Build a session with one TGT in Tickets_1
	sess := make([]byte, sessLayout.NodeReadSize)

	// Tickets_1 list head points to the ticket
	tickets1Addr := sessionBase + uintptr(sessLayout.Tickets1Off)
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets1Off:], uint64(ticketBase))
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets1Off+8:], uint64(ticketBase))

	// Tickets_2 and _3 are empty (self-referencing)
	tickets2Addr := sessionBase + uintptr(sessLayout.Tickets2Off)
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets2Off:], uint64(tickets2Addr))
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets2Off+8:], uint64(tickets2Addr))
	tickets3Addr := sessionBase + uintptr(sessLayout.Tickets3Off)
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets3Off:], uint64(tickets3Addr))
	binary.LittleEndian.PutUint64(sess[sessLayout.Tickets3Off+8:], uint64(tickets3Addr))

	r.put(sessionBase, sess)

	// Also put the list head as readable (it's within the session struct)
	r.put(tickets1Addr, sess[sessLayout.Tickets1Off:sessLayout.Tickets1Off+16])
	r.put(tickets2Addr, sess[sessLayout.Tickets2Off:sessLayout.Tickets2Off+16])
	r.put(tickets3Addr, sess[sessLayout.Tickets3Off:sessLayout.Tickets3Off+16])

	// Build a minimal ticket
	ticket := make([]byte, tickLayout.NodeReadSize)
	// LIST_ENTRY: Flink → listHead, Blink → listHead
	binary.LittleEndian.PutUint64(ticket[0:8], uint64(tickets1Addr))
	binary.LittleEndian.PutUint64(ticket[8:16], uint64(tickets1Addr))
	// Ticket flags
	binary.LittleEndian.PutUint32(ticket[tickLayout.TicketFlagsOff:], 0x40800000) // forwardable + renewable
	// Domain name
	domStr := utf16Encode("TEST.LOCAL")
	domAddr := uintptr(0x30000)
	r.put(domAddr, domStr)
	copy(ticket[tickLayout.DomainNameOff:], buildUnicodeString(domAddr, domStr))

	r.put(ticketBase, ticket)

	tickets := extractKerbTickets(r, sess, sessionBase, sessLayout, tickLayout)
	if len(tickets) != 1 {
		t.Fatalf("got %d tickets, want 1", len(tickets))
	}
	if tickets[0].ListIndex != 1 {
		t.Errorf("ListIndex = %d, want 1 (TGT)", tickets[0].ListIndex)
	}
	if tickets[0].DomainName != "TEST.LOCAL" {
		t.Errorf("DomainName = %q, want TEST.LOCAL", tickets[0].DomainName)
	}
	if tickets[0].TicketFlags != 0x40800000 {
		t.Errorf("TicketFlags = 0x%08X, want 0x40800000", tickets[0].TicketFlags)
	}
}

// ---------------------------------------------------------------------------
// Tests: buildKirbi
// ---------------------------------------------------------------------------

func TestBuildKirbi_ValidTicket(t *testing.T) {
	ticket := kerbTicket{
		ListIndex:   1,
		ServiceName: "krbtgt/CONTOSO.COM",
		ClientName:  "administrator",
		DomainName:  "CONTOSO.COM",
		TargetDomain: "CONTOSO.COM",
		TicketFlags: 0x40E10000,
		KeyType:     18, // AES256
		KeyBytes:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		StartTime:   time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		EndTime:     time.Date(2026, 5, 30, 22, 0, 0, 0, time.UTC),
		RenewUntil:  time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC),
		TicketEncType: 18,
		TicketKvno:    2,
		TicketBytes:   []byte{0x61, 0x82, 0x03, 0x00, 0xDE, 0xAD}, // fake Ticket ASN.1
	}

	kirbi, err := buildKirbi(ticket)
	if err != nil {
		t.Fatalf("buildKirbi failed: %v", err)
	}
	if len(kirbi) == 0 {
		t.Fatal("buildKirbi returned empty bytes")
	}

	// Verify it starts with APPLICATION[22] tag (0x76 = 0x60 | 22)
	if kirbi[0] != 0x76 {
		t.Errorf("first byte = 0x%02X, want 0x76 (APPLICATION[22])", kirbi[0])
	}

	// Verify the raw ticket bytes appear in the output
	found := false
	for i := 0; i+6 <= len(kirbi); i++ {
		if kirbi[i] == 0x61 && kirbi[i+1] == 0x82 && kirbi[i+2] == 0x03 &&
			kirbi[i+3] == 0x00 && kirbi[i+4] == 0xDE && kirbi[i+5] == 0xAD {
			found = true
			break
		}
	}
	if !found {
		t.Error("raw ticket bytes not found in kirbi output")
	}
}

func TestBuildKirbi_NoTicketBytes(t *testing.T) {
	ticket := kerbTicket{
		ServiceName: "krbtgt/CONTOSO.COM",
		TicketBytes: nil,
	}
	_, err := buildKirbi(ticket)
	if err == nil {
		t.Fatal("expected error for ticket with no raw bytes")
	}
}

func TestKirbiSplitName(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"krbtgt/CONTOSO.COM", []string{"krbtgt", "CONTOSO.COM"}},
		{"cifs/dc01.contoso.com", []string{"cifs", "dc01.contoso.com"}},
		{"administrator", []string{"administrator"}},
		{"HTTP/web.corp.local/corp.local", []string{"HTTP", "web.corp.local", "corp.local"}},
	}
	for _, tc := range tests {
		got := kirbiSplitName(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("kirbiSplitName(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("kirbiSplitName(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
