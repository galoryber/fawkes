package commands

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// bufferReader is a testing-only lsassReader backed by an exact-address page
// table. Reads must hit a registered page exactly (the walker reads each
// node at its base address, so this is sufficient).
type bufferReader struct {
	pages map[uintptr][]byte
	// readErr, when non-nil, is returned for any read at addrs in errOn.
	readErr error
	errOn   map[uintptr]bool
}

func newBufferReader() *bufferReader {
	return &bufferReader{pages: map[uintptr][]byte{}, errOn: map[uintptr]bool{}}
}

func (b *bufferReader) put(addr uintptr, page []byte) {
	cp := make([]byte, len(page))
	copy(cp, page)
	b.pages[addr] = cp
}

func (b *bufferReader) Read(addr uintptr, size uint32) ([]byte, error) {
	if b.readErr != nil && b.errOn[addr] {
		return nil, b.readErr
	}
	page, ok := b.pages[addr]
	if !ok {
		return nil, errors.New("bufferReader: no page registered at requested address")
	}
	if uint32(len(page)) < size {
		return nil, errors.New("bufferReader: page smaller than requested size")
	}
	out := make([]byte, size)
	copy(out, page[:size])
	return out, nil
}

// makeNode builds a 0x100-byte node buffer with Flink+Blink at +0x00/+0x08
// and `payload` written at offset 0x40. Used to inject synthetic LUIDs into
// the cross-reference scanner.
func makeNode(flink, blink uintptr, payload []byte) []byte {
	n := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(n[0:8], uint64(flink))
	binary.LittleEndian.PutUint64(n[8:16], uint64(blink))
	if len(payload) > 0 {
		copy(n[0x40:], payload)
	}
	return n
}

// makeHead builds a 16-byte sentinel containing only Flink+Blink.
func makeHead(flink, blink uintptr) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint64(h[0:8], uint64(flink))
	binary.LittleEndian.PutUint64(h[8:16], uint64(blink))
	return h
}

func TestWalkLogonSessionList_ThreeNodesCleanTerminate(t *testing.T) {
	const (
		head = uintptr(0x1000)
		n1   = uintptr(0x2000)
		n2   = uintptr(0x3000)
		n3   = uintptr(0x4000)
	)
	r := newBufferReader()
	// circular doubly-linked list: head ↔ n1 ↔ n2 ↔ n3 ↔ head
	r.put(head, makeHead(n1, n3))
	r.put(n1, makeNode(n2, head, nil))
	r.put(n2, makeNode(n3, n1, nil))
	r.put(n3, makeNode(head, n2, nil))

	nodes, err := walkLogonSessionList(r, head, 0x100, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("walked %d nodes, want 3", len(nodes))
	}
	wantAddrs := []uintptr{n1, n2, n3}
	for i, n := range nodes {
		if n.Address != wantAddrs[i] {
			t.Errorf("node[%d].Address = 0x%X, want 0x%X", i, n.Address, wantAddrs[i])
		}
	}
	if nodes[0].Flink != n2 || nodes[1].Flink != n3 || nodes[2].Flink != head {
		t.Errorf("Flink chain wrong: %x -> %x -> %x", nodes[0].Flink, nodes[1].Flink, nodes[2].Flink)
	}
	if nodes[0].Blink != head || nodes[1].Blink != n1 || nodes[2].Blink != n2 {
		t.Errorf("Blink chain wrong: %x -> %x -> %x", nodes[0].Blink, nodes[1].Blink, nodes[2].Blink)
	}
}

func TestWalkLogonSessionList_EmptyList(t *testing.T) {
	const head = uintptr(0x1000)
	r := newBufferReader()
	// Empty list: head.Flink == head
	r.put(head, makeHead(head, head))
	_, err := walkLogonSessionList(r, head, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' error, got %v", err)
	}
}

func TestWalkLogonSessionList_NullFlinkHead(t *testing.T) {
	const head = uintptr(0x1000)
	r := newBufferReader()
	r.put(head, makeHead(0, 0))
	_, err := walkLogonSessionList(r, head, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' error for null Flink head, got %v", err)
	}
}

func TestWalkLogonSessionList_CycleDetection(t *testing.T) {
	const (
		head = uintptr(0x1000)
		n1   = uintptr(0x2000)
		n2   = uintptr(0x3000)
	)
	r := newBufferReader()
	r.put(head, makeHead(n1, n2))
	r.put(n1, makeNode(n2, head, nil))
	r.put(n2, makeNode(n1, n1, nil)) // n2.Flink loops back to n1 instead of returning to head
	nodes, err := walkLogonSessionList(r, head, 0x100, 64)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes recovered before cycle detection, got %d", len(nodes))
	}
}

func TestWalkLogonSessionList_NullFlinkMidWalk(t *testing.T) {
	const (
		head = uintptr(0x1000)
		n1   = uintptr(0x2000)
	)
	r := newBufferReader()
	r.put(head, makeHead(n1, n1))
	r.put(n1, makeNode(0, head, nil)) // n1.Flink is null mid-walk
	nodes, err := walkLogonSessionList(r, head, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "null Flink") {
		t.Fatalf("expected null Flink error, got %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node before null Flink halt, got %d", len(nodes))
	}
}

func TestWalkLogonSessionList_ReadFailureMidWalk(t *testing.T) {
	const (
		head = uintptr(0x1000)
		n1   = uintptr(0x2000)
		n2   = uintptr(0x3000)
	)
	r := newBufferReader()
	r.put(head, makeHead(n1, n2))
	r.put(n1, makeNode(n2, head, nil))
	// n2 deliberately not registered → Read at 0x3000 will fail
	nodes, err := walkLogonSessionList(r, head, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "read node") {
		t.Fatalf("expected 'read node' error, got %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node before failure, got %d", len(nodes))
	}
}

func TestWalkLogonSessionList_MaxNodesCap(t *testing.T) {
	// Build a malicious list that NEVER returns to head: each node's Flink
	// points to a fresh address, walker keeps going until the cap fires.
	const head = uintptr(0x1000)
	r := newBufferReader()
	addrs := []uintptr{0x2000, 0x3000, 0x4000, 0x5000, 0x6000}
	r.put(head, makeHead(addrs[0], addrs[len(addrs)-1]))
	for i, a := range addrs {
		next := uintptr(0xDEAD0000) // unregistered, would fail next read
		if i < len(addrs)-1 {
			next = addrs[i+1]
		}
		r.put(a, makeNode(next, head, nil))
	}
	nodes, err := walkLogonSessionList(r, head, 0x100, 3)
	if err == nil || !strings.Contains(err.Error(), "safety cap") {
		t.Fatalf("expected safety cap error, got %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("expected exactly 3 nodes (cap), got %d", len(nodes))
	}
}

func TestWalkLogonSessionList_RejectsBadInputs(t *testing.T) {
	r := newBufferReader()
	if _, err := walkLogonSessionList(nil, 0x1000, 0x100, 8); err == nil {
		t.Error("nil reader: expected error")
	}
	if _, err := walkLogonSessionList(r, 0, 0x100, 8); err == nil {
		t.Error("zero anchor: expected error")
	}
	if _, err := walkLogonSessionList(r, 0x1000, 8, 8); err == nil {
		t.Error("nodeReadSize<16: expected error")
	}
}

func TestFindLogonSessionListAnchor_SignaturePresent(t *testing.T) {
	// Build a synthetic lsasrv buffer with the LogonSessionList signature at
	// offset 0x500. The MOV at offset +9 (= buffer offset 0x509) has a disp32
	// value of 0x00001000, so its target is at instr_end + 0x1000:
	//   instrStart = 0x509, instrLen = 7  →  instrEnd = 0x510
	//   target offset = 0x510 + 0x1000 = 0x1510
	pat, mask, err := parseHexPattern(LogonSessionListSignature)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pat) != 23 || len(mask) != 23 {
		t.Fatalf("signature length: got pat=%d mask=%d, want 23/23", len(pat), len(mask))
	}

	buf := make([]byte, 0x4000)
	const sigOffset = 0x500
	for i, b := range pat {
		if mask[i] {
			buf[sigOffset+i] = 0x00 // wildcard byte content doesn't matter for finding
		} else {
			buf[sigOffset+i] = b
		}
	}
	// Stamp the disp32 inside the MOV (instruction at +9, disp at +12 within the match)
	const dispBufOffset = sigOffset + 9 + 3
	binary.LittleEndian.PutUint32(buf[dispBufOffset:dispBufOffset+4], 0x00001000)

	const lsasrvBase = uintptr(0x7FFFAAAA0000)
	got, err := findLogonSessionListAnchor(buf, lsasrvBase)
	if err != nil {
		t.Fatalf("findLogonSessionListAnchor: %v", err)
	}
	wantOffset := uintptr(sigOffset + 9 + 7 + 0x1000) // instrStart + instrLen + disp
	want := lsasrvBase + wantOffset
	if got != want {
		t.Errorf("anchor = 0x%X, want 0x%X (offset 0x%X)", got, want, wantOffset)
	}
}

func TestFindLogonSessionListAnchor_NegativeDisplacement(t *testing.T) {
	// Negative disp32 (back-reference): target is in an earlier .data page.
	pat, mask, _ := parseHexPattern(LogonSessionListSignature)
	buf := make([]byte, 0x4000)
	const sigOffset = 0x2000
	for i, b := range pat {
		if !mask[i] {
			buf[sigOffset+i] = b
		}
	}
	const dispBufOffset = sigOffset + 9 + 3
	negDisp := int32(-0x800)
	binary.LittleEndian.PutUint32(buf[dispBufOffset:dispBufOffset+4], uint32(negDisp)) // -2048
	const lsasrvBase = uintptr(0x180000000)
	got, err := findLogonSessionListAnchor(buf, lsasrvBase)
	if err != nil {
		t.Fatalf("findLogonSessionListAnchor: %v", err)
	}
	wantOffset := uintptr(sigOffset + 9 + 7 - 0x800)
	want := lsasrvBase + wantOffset
	if got != want {
		t.Errorf("anchor = 0x%X, want 0x%X", got, want)
	}
}

func TestFindLogonSessionListAnchor_NotFound(t *testing.T) {
	buf := make([]byte, 0x1000) // all zeros; no signature
	_, err := findLogonSessionListAnchor(buf, 0x180000000)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got %v", err)
	}
}

func TestFindLogonSessionListAnchor_TargetOutsideBuffer(t *testing.T) {
	// Place the signature near the end of the buffer with a positive disp32
	// big enough to overshoot the buffer. resolveRIPRelative should mark the
	// match as out-of-buffer.
	pat, mask, _ := parseHexPattern(LogonSessionListSignature)
	buf := make([]byte, 0x100+len(pat)+0x10) // small buffer
	sigOffset := 0x100
	for i, b := range pat {
		if !mask[i] {
			buf[sigOffset+i] = b
		}
	}
	dispBufOffset := sigOffset + 9 + 3
	binary.LittleEndian.PutUint32(buf[dispBufOffset:dispBufOffset+4], 0x00100000) // way past EOF
	_, err := findLogonSessionListAnchor(buf, 0x180000000)
	if err == nil || !strings.Contains(err.Error(), "outside captured") {
		t.Fatalf("expected 'outside captured' error, got %v", err)
	}
}

func TestScanRawForLUID(t *testing.T) {
	luid := uint64(0x000000C8DEADBEEF)
	raw := makeNode(0, 0, []byte{0x11, 0x22, 0x33, 0xEF, 0xBE, 0xAD, 0xDE, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x99})
	if !scanRawForLUID(raw, luid) {
		t.Errorf("scanRawForLUID: expected match for 0x%X", luid)
	}
	if scanRawForLUID(raw, 0x1122334455667788) {
		t.Errorf("scanRawForLUID: false positive for unrelated LUID")
	}
	if scanRawForLUID([]byte{1, 2, 3}, luid) {
		t.Errorf("scanRawForLUID: short buffer should not match")
	}
}
