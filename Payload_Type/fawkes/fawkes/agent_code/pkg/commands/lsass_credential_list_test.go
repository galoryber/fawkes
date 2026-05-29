package commands

import (
	"encoding/binary"
	"strings"
	"testing"
)

// stampCredentialListEntry writes a 0x28-byte CREDENTIAL_LIST entry
// (Flink+0, Blink+8, creds.next+0x10, AuthPkgId+0x18, PrimaryCreds+0x20).
func stampCredentialListEntry(buf []byte, flink, blink uintptr, authPkgID uint32, primaryPtr uintptr) {
	binary.LittleEndian.PutUint64(buf[0:8], uint64(flink))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(blink))
	// buf[0x10:0x18] = Credentials.next (leave zero)
	binary.LittleEndian.PutUint32(buf[0x18:0x1C], authPkgID)
	// buf[0x1C:0x20] = alignment pad (leave zero)
	binary.LittleEndian.PutUint64(buf[0x20:0x28], uint64(primaryPtr))
}

// makePrimaryEnc builds a 0x28-byte PRIMARY_CREDENTIALS envelope:
//
//	+0x00  next (leave zero)
//	+0x08  Primary (ANSI_STRING — auth package name)
//	+0x18  Credentials (LSA_UNICODE_STRING — encrypted blob)
func makePrimaryEnc(primaryBuf, credBuf uintptr, primaryLenBytes, credLenBytes uint16) []byte {
	raw := make([]byte, primaryCredentialEncSize)
	// next at +0 left zero
	stampUnicodeStringHeader(raw, primaryEncPrimaryOff, primaryLenBytes, primaryBuf)
	stampUnicodeStringHeader(raw, primaryEncCredentialOff, credLenBytes, credBuf)
	return raw
}

func TestAuthPackageName_KnownAndUnknown(t *testing.T) {
	cases := map[uint32]string{
		0:    "MSV1_0",
		1:    "Custom1",
		2:    "Kerberos",
		3:    "WDigest",
		4:    "TSPkg",
		5:    "PKU2U",
		6:    "CloudAP",
		9999: "Unknown(9999)",
		0x4F: "Unknown(79)",
	}
	for id, want := range cases {
		if got := authPackageName(id); got != want {
			t.Errorf("authPackageName(%d) = %q, want %q", id, got, want)
		}
	}
}

func TestReadLSAUnicodeRawBytes_RoundTrip(t *testing.T) {
	const blobAddr = uintptr(0xCC0000)
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55} // 11 bytes (odd)
	r := newBufferReader()
	r.put(blobAddr, payload)

	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, uint16(len(payload)), blobAddr)

	bytes, addr, length, err := readLSAUnicodeRawBytes(r, raw, 0, ciphertextSanityMax)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != blobAddr {
		t.Errorf("addr = 0x%X, want 0x%X", addr, blobAddr)
	}
	if length != uint16(len(payload)) {
		t.Errorf("length = %d, want %d", length, len(payload))
	}
	if string(bytes) != string(payload) {
		t.Errorf("bytes = %v, want %v", bytes, payload)
	}
}

func TestReadLSAUnicodeRawBytes_AcceptsOddLength(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 7, 0xAA0000)
	r := newBufferReader()
	r.put(0xAA0000, []byte{1, 2, 3, 4, 5, 6, 7})

	bytes, _, length, err := readLSAUnicodeRawBytes(r, raw, 0, ciphertextSanityMax)
	if err != nil {
		t.Fatalf("expected odd-length to succeed for raw bytes, got error: %v", err)
	}
	if length != 7 || len(bytes) != 7 {
		t.Errorf("length=%d len(bytes)=%d, want 7/7", length, len(bytes))
	}
}

func TestReadLSAUnicodeRawBytes_RejectsSanityCap(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 5000, 0xAA0000)
	_, _, _, err := readLSAUnicodeRawBytes(newBufferReader(), raw, 0, 4096)
	if err == nil || !strings.Contains(err.Error(), "sanity cap") {
		t.Errorf("expected sanity-cap error, got %v", err)
	}
}

func TestReadLSAUnicodeRawBytes_NilReader(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 8, 0xAA0000)
	_, _, _, err := readLSAUnicodeRawBytes(nil, raw, 0, ciphertextSanityMax)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestReadLSAUnicodeRawBytes_EmptyLengthOrNullBuffer(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 0, 0xDEAD0000)
	bytes, addr, length, err := readLSAUnicodeRawBytes(newBufferReader(), raw, 0, ciphertextSanityMax)
	if err != nil || bytes != nil || length != 0 || addr != 0xDEAD0000 {
		t.Errorf("Length=0: bytes=%v addr=0x%X length=%d err=%v; want nil/0xDEAD0000/0/nil", bytes, addr, length, err)
	}

	stampUnicodeStringHeader(raw, 0, 16, 0)
	bytes, addr, length, err = readLSAUnicodeRawBytes(newBufferReader(), raw, 0, ciphertextSanityMax)
	if err != nil || bytes != nil || addr != 0 || length != 16 {
		t.Errorf("Buffer=0: bytes=%v addr=0x%X length=%d err=%v; want nil/0/16/nil", bytes, addr, length, err)
	}
}

func TestReadPrimaryCredentialEnc_FullEnvelope(t *testing.T) {
	const (
		envelopeAddr   = uintptr(0x1000)
		primaryBufAddr = uintptr(0x2000) // auth package name (e.g., "Primary")
		credBufAddr    = uintptr(0x4000) // encrypted credential blob
	)
	pkgName := utf16LEBytes("Primary")
	cipher := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	r := newBufferReader()
	r.put(primaryBufAddr, pkgName)
	r.put(credBufAddr, cipher)
	r.put(envelopeAddr, makePrimaryEnc(primaryBufAddr, credBufAddr, uint16(len(pkgName)), uint16(len(cipher))))

	p, err := readPrimaryCredentialEnc(r, envelopeAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.EncryptedAddress != credBufAddr {
		t.Errorf("EncryptedAddress = 0x%X, want 0x%X", p.EncryptedAddress, credBufAddr)
	}
	if p.EncryptedLength != uint16(len(cipher)) {
		t.Errorf("EncryptedLength = %d, want %d", p.EncryptedLength, len(cipher))
	}
	if string(p.EncryptedBytes) != string(cipher) {
		t.Errorf("EncryptedBytes = %v, want %v", p.EncryptedBytes, cipher)
	}
	if len(p.ParseErrors) != 0 {
		t.Errorf("unexpected ParseErrors: %v", p.ParseErrors)
	}
}

func TestReadPrimaryCredentialEnc_PartialFailureSurvives(t *testing.T) {
	const (
		envelopeAddr   = uintptr(0x1000)
		primaryBufAddr = uintptr(0x2000) // intentionally NOT registered → read fails
		credBufAddr    = uintptr(0x4000)
	)
	cipher := []byte{0x11, 0x22}
	r := newBufferReader()
	r.put(credBufAddr, cipher)
	r.put(envelopeAddr, makePrimaryEnc(primaryBufAddr, credBufAddr, 8, uint16(len(cipher))))

	p, err := readPrimaryCredentialEnc(r, envelopeAddr)
	if err != nil {
		t.Fatalf("unexpected envelope error: %v", err)
	}
	if p.UserName != "" {
		t.Errorf("UserName = %q, want empty (Primary read failed)", p.UserName)
	}
	if string(p.EncryptedBytes) != string(cipher) {
		t.Errorf("EncryptedBytes = %v, want %v", p.EncryptedBytes, cipher)
	}
	if len(p.ParseErrors) != 1 || !strings.Contains(p.ParseErrors[0], "Primary") {
		t.Errorf("expected one Primary ParseError, got %v", p.ParseErrors)
	}
}

func TestReadPrimaryCredentialEnc_ZeroAddr(t *testing.T) {
	_, err := readPrimaryCredentialEnc(newBufferReader(), 0)
	if err == nil || !strings.Contains(err.Error(), "zero PrimaryCredentials_data") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadPrimaryCredentialEnc_EnvelopeReadFails(t *testing.T) {
	_, err := readPrimaryCredentialEnc(newBufferReader(), 0xDEAD)
	if err == nil || !strings.Contains(err.Error(), "read PRIMARY_CREDENTIALS") {
		t.Errorf("expected envelope read failure, got %v", err)
	}
}

func TestWalkCredentialList_ZeroHead(t *testing.T) {
	entries, err := walkCredentialList(newBufferReader(), 0, 16)
	if err != nil || entries != nil {
		t.Errorf("expected nil/nil for zero head, got entries=%d err=%v", len(entries), err)
	}
}

func TestWalkCredentialList_NilReader(t *testing.T) {
	_, err := walkCredentialList(nil, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestWalkCredentialList_SingleEntryWithPrimary(t *testing.T) {
	const (
		headAddr       = uintptr(0x08000) // sentinel head
		entryAddr      = uintptr(0x10000) // real entry
		primaryAddr    = uintptr(0x20000)
		primaryBufAddr = uintptr(0x30000) // auth package name
		credBufAddr    = uintptr(0x40000) // encrypted blob
	)
	pkgName := []byte("Primary")
	cipher := []byte{0xAA, 0xBB}
	r := newBufferReader()

	// Sentinel head: Flink → entryAddr
	head := make([]byte, 8)
	binary.LittleEndian.PutUint64(head, uint64(entryAddr))
	r.put(headAddr, head)

	// Real entry: Flink → headAddr (wrap back to sentinel = termination)
	entry := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(entry, headAddr, headAddr, 0 /*MSV1_0*/, primaryAddr)
	r.put(entryAddr, entry)

	r.put(primaryAddr, makePrimaryEnc(primaryBufAddr, credBufAddr, uint16(len(pkgName)), uint16(len(cipher))))
	r.put(primaryBufAddr, pkgName)
	r.put(credBufAddr, cipher)

	entries, err := walkCredentialList(r, headAddr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.AuthPackageId != 0 || e.AuthPackageName != "MSV1_0" {
		t.Errorf("AuthPackage id=%d name=%q, want 0/MSV1_0", e.AuthPackageId, e.AuthPackageName)
	}
	if e.PrimaryCredentialsDataPtr != primaryAddr {
		t.Errorf("PrimaryCredentialsDataPtr = 0x%X, want 0x%X", e.PrimaryCredentialsDataPtr, primaryAddr)
	}
	if e.Primary == nil {
		t.Fatal("Primary is nil")
	}
	if string(e.Primary.EncryptedBytes) != string(cipher) {
		t.Errorf("Primary.EncryptedBytes = %v, want %v", e.Primary.EncryptedBytes, cipher)
	}
	if e.PrimaryReadErr != "" {
		t.Errorf("unexpected PrimaryReadErr: %q", e.PrimaryReadErr)
	}
}

func TestWalkCredentialList_ChainTerminatesAtSentinel(t *testing.T) {
	const (
		headAddr   = uintptr(0x08000)
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()

	// Sentinel head: Flink → entry1
	head := make([]byte, 8)
	binary.LittleEndian.PutUint64(head, uint64(entry1Addr))
	r.put(headAddr, head)

	e1 := make([]byte, credentialListEntryReadSize)
	e2 := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(e1, entry2Addr, headAddr, 2 /*Kerberos*/, 0)
	stampCredentialListEntry(e2, headAddr, entry1Addr, 0 /*MSV1_0*/, 0) // wraps to head = clean termination
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, headAddr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].AuthPackageName != "Kerberos" {
		t.Errorf("entry[0] = %q, want Kerberos", entries[0].AuthPackageName)
	}
	if entries[1].AuthPackageName != "MSV1_0" {
		t.Errorf("entry[1] = %q, want MSV1_0", entries[1].AuthPackageName)
	}
}

func TestWalkCredentialList_CycleDetected(t *testing.T) {
	const (
		headAddr   = uintptr(0x08000)
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()

	head := make([]byte, 8)
	binary.LittleEndian.PutUint64(head, uint64(entry1Addr))
	r.put(headAddr, head)

	e1 := make([]byte, credentialListEntryReadSize)
	e2 := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(e1, entry2Addr, headAddr, 0, 0)
	stampCredentialListEntry(e2, entry1Addr, entry2Addr, 0, 0) // cycle: entry2 → entry1
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, headAddr, 16)
	// Cycle is now treated as clean termination (not error)
	if err != nil {
		t.Errorf("expected nil error for cycle (clean termination), got %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries before cycle detect, want 2", len(entries))
	}
}

func TestWalkCredentialList_SafetyCap(t *testing.T) {
	const headAddr = uintptr(0x08000)
	addrs := []uintptr{0x10000, 0x11000, 0x12000, 0x13000, 0x14000}
	r := newBufferReader()

	head := make([]byte, 8)
	binary.LittleEndian.PutUint64(head, uint64(addrs[0]))
	r.put(headAddr, head)

	for i, a := range addrs {
		e := make([]byte, credentialListEntryReadSize)
		var flink uintptr
		if i+1 < len(addrs) {
			flink = addrs[i+1]
		}
		stampCredentialListEntry(e, flink, headAddr, 0, 0)
		r.put(a, e)
	}
	entries, err := walkCredentialList(r, headAddr, 3)
	if err == nil || !strings.Contains(err.Error(), "safety cap") {
		t.Errorf("expected safety-cap error, got %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

func TestWalkCredentialList_HeadFlinkIsZero(t *testing.T) {
	const headAddr = uintptr(0x08000)
	r := newBufferReader()
	head := make([]byte, 8) // Flink = 0 (empty list)
	r.put(headAddr, head)

	entries, err := walkCredentialList(r, headAddr, 16)
	if err != nil || entries != nil {
		t.Errorf("expected nil/nil for empty sentinel, got entries=%v err=%v", entries, err)
	}
}

func TestWalkCredentialList_HeadFlinkPointsToSelf(t *testing.T) {
	const headAddr = uintptr(0x08000)
	r := newBufferReader()
	head := make([]byte, 8)
	binary.LittleEndian.PutUint64(head, uint64(headAddr)) // Flink → self = empty
	r.put(headAddr, head)

	entries, err := walkCredentialList(r, headAddr, 16)
	if err != nil || entries != nil {
		t.Errorf("expected nil/nil for self-referencing sentinel, got entries=%v err=%v", entries, err)
	}
}
