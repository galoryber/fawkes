package commands

import (
	"encoding/binary"
	"strings"
	"testing"
)

// stampCredentialEntry writes a 0x18-byte KIWI_MSV1_0_CREDENTIALS entry
// (next+0, AuthPkgId+0x08, PrimaryCreds+0x10).
func stampCredentialEntry(buf []byte, next uintptr, authPkgID uint32, primaryPtr uintptr) {
	binary.LittleEndian.PutUint64(buf[0:8], uint64(next))
	binary.LittleEndian.PutUint32(buf[0x08:0x0C], authPkgID)
	// buf[0x0C:0x10] = alignment pad (leave zero)
	binary.LittleEndian.PutUint64(buf[0x10:0x18], uint64(primaryPtr))
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
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55}
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
		t.Errorf("Length=0: bytes=%v addr=0x%X length=%d err=%v", bytes, addr, length, err)
	}

	stampUnicodeStringHeader(raw, 0, 16, 0)
	bytes, addr, length, err = readLSAUnicodeRawBytes(newBufferReader(), raw, 0, ciphertextSanityMax)
	if err != nil || bytes != nil || addr != 0 || length != 16 {
		t.Errorf("Buffer=0: bytes=%v addr=0x%X length=%d err=%v", bytes, addr, length, err)
	}
}

func TestReadPrimaryCredentialEnc_FullEnvelope(t *testing.T) {
	const (
		envelopeAddr   = uintptr(0x1000)
		primaryBufAddr = uintptr(0x2000)
		credBufAddr    = uintptr(0x4000)
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
		t.Errorf("EncryptedBytes mismatch")
	}
	if len(p.ParseErrors) != 0 {
		t.Errorf("unexpected ParseErrors: %v", p.ParseErrors)
	}
}

func TestReadPrimaryCredentialEnc_PartialFailureSurvives(t *testing.T) {
	const (
		envelopeAddr   = uintptr(0x1000)
		primaryBufAddr = uintptr(0x2000) // NOT registered → read fails
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
	if string(p.EncryptedBytes) != string(cipher) {
		t.Errorf("EncryptedBytes mismatch")
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
		t.Errorf("expected nil/nil for zero head, got entries=%v err=%v", entries, err)
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
		entryAddr      = uintptr(0x10000)
		primaryAddr    = uintptr(0x20000)
		primaryBufAddr = uintptr(0x30000)
		credBufAddr    = uintptr(0x40000)
	)
	pkgName := utf16LEBytes("Primary")
	cipher := []byte{0xAA, 0xBB}
	r := newBufferReader()

	entry := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(entry, 0, 0 /*MSV1_0*/, primaryAddr)
	r.put(entryAddr, entry)

	r.put(primaryAddr, makePrimaryEnc(primaryBufAddr, credBufAddr, uint16(len(pkgName)), uint16(len(cipher))))
	r.put(primaryBufAddr, pkgName)
	r.put(credBufAddr, cipher)

	entries, err := walkCredentialList(r, entryAddr, 16)
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
	if e.Primary == nil {
		t.Fatal("Primary is nil")
	}
	if string(e.Primary.EncryptedBytes) != string(cipher) {
		t.Errorf("Primary.EncryptedBytes mismatch")
	}
}

func TestWalkCredentialList_ChainTerminatesAtNull(t *testing.T) {
	const (
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()

	e1 := make([]byte, credentialEntryReadSize)
	e2 := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(e1, entry2Addr, 0 /*MSV1_0*/, 0)
	stampCredentialEntry(e2, 0, 3 /*WDigest*/, 0) // next=0 = termination
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, entry1Addr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].AuthPackageName != "MSV1_0" {
		t.Errorf("entry[0] = %q, want MSV1_0", entries[0].AuthPackageName)
	}
	if entries[1].AuthPackageName != "WDigest" {
		t.Errorf("entry[1] = %q, want WDigest", entries[1].AuthPackageName)
	}
}

func TestWalkCredentialList_CycleDetected(t *testing.T) {
	const (
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()

	e1 := make([]byte, credentialEntryReadSize)
	e2 := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(e1, entry2Addr, 0, 0)
	stampCredentialEntry(e2, entry1Addr, 0, 0) // cycle
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, entry1Addr, 16)
	if err != nil {
		t.Errorf("expected nil error for cycle, got %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

func TestWalkCredentialList_SafetyCap(t *testing.T) {
	addrs := []uintptr{0x10000, 0x11000, 0x12000, 0x13000, 0x14000}
	r := newBufferReader()

	for i, a := range addrs {
		e := make([]byte, credentialEntryReadSize)
		var next uintptr
		if i+1 < len(addrs) {
			next = addrs[i+1]
		}
		stampCredentialEntry(e, next, 0, 0)
		r.put(a, e)
	}
	entries, err := walkCredentialList(r, addrs[0], 3)
	if err == nil || !strings.Contains(err.Error(), "safety cap") {
		t.Errorf("expected safety-cap error, got %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

func TestWalkCredentialList_SingleEntryNextIsNull(t *testing.T) {
	const entryAddr = uintptr(0x08000)
	r := newBufferReader()
	entry := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(entry, 0, 3, 0) // WDigest, next=NULL
	r.put(entryAddr, entry)

	entries, err := walkCredentialList(r, entryAddr, 16)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].AuthPackageName != "WDigest" {
		t.Errorf("expected WDigest, got %s", entries[0].AuthPackageName)
	}
}

func TestWalkCredentialList_SingleEntrySelfRef(t *testing.T) {
	const entryAddr = uintptr(0x08000)
	r := newBufferReader()
	entry := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(entry, entryAddr, 0, 0) // next → self
	r.put(entryAddr, entry)

	entries, err := walkCredentialList(r, entryAddr, 16)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestWalkPrimaryCredentialChain_MultipleEntries(t *testing.T) {
	const (
		primary1Addr    = uintptr(0x20000)
		primary2Addr    = uintptr(0x21000)
		pkg1BufAddr     = uintptr(0x30000)
		cred1BufAddr    = uintptr(0x40000)
		pkg2BufAddr     = uintptr(0x31000)
		cred2BufAddr    = uintptr(0x41000)
	)
	r := newBufferReader()

	// First entry: "Primary" → encrypted MSV1_0 blob, next → primary2Addr
	pkg1 := utf16LEBytes("Primary")
	cipher1 := []byte{0xAA, 0xBB}
	enc1 := makePrimaryEnc(pkg1BufAddr, cred1BufAddr, uint16(len(pkg1)), uint16(len(cipher1)))
	// Set next pointer at +0x00 to chain to second entry
	binary.LittleEndian.PutUint64(enc1[0:8], uint64(primary2Addr))
	r.put(primary1Addr, enc1)
	r.put(pkg1BufAddr, pkg1)
	r.put(cred1BufAddr, cipher1)

	// Second entry: "Kerberos-Newer-Keys" → encrypted Kerberos blob, next → 0
	pkg2 := utf16LEBytes("Kerberos-Newer-Keys")
	cipher2 := []byte{0xCC, 0xDD, 0xEE}
	enc2 := makePrimaryEnc(pkg2BufAddr, cred2BufAddr, uint16(len(pkg2)), uint16(len(cipher2)))
	r.put(primary2Addr, enc2)
	r.put(pkg2BufAddr, pkg2)
	r.put(cred2BufAddr, cipher2)

	entries, err := walkPrimaryCredentialChain(r, primary1Addr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if string(entries[0].EncryptedBytes) != string(cipher1) {
		t.Errorf("entry[0] cipher mismatch")
	}
	if string(entries[1].EncryptedBytes) != string(cipher2) {
		t.Errorf("entry[1] cipher mismatch")
	}
}

func TestWalkPrimaryCredentialChain_NullTerminated(t *testing.T) {
	const (
		primaryAddr = uintptr(0x22000)
		pkgBufAddr  = uintptr(0x32000)
		credBufAddr = uintptr(0x42000)
	)
	r := newBufferReader()

	pkg := utf16LEBytes("WDigest")
	cipher := []byte{0x11}
	enc := makePrimaryEnc(pkgBufAddr, credBufAddr, uint16(len(pkg)), uint16(len(cipher)))
	r.put(primaryAddr, enc)
	r.put(pkgBufAddr, pkg)
	r.put(credBufAddr, cipher)

	entries, err := walkPrimaryCredentialChain(r, primaryAddr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
}

func TestWalkPrimaryCredentialChain_ZeroHead(t *testing.T) {
	entries, err := walkPrimaryCredentialChain(newBufferReader(), 0, 16)
	if err != nil || entries != nil {
		t.Errorf("expected nil/nil for zero head, got entries=%v err=%v", entries, err)
	}
}

func TestWalkCredentialList_PrimaryEntries(t *testing.T) {
	const (
		entryAddr      = uintptr(0x50000)
		primary1Addr   = uintptr(0x60000)
		primary2Addr   = uintptr(0x61000)
		pkg1BufAddr    = uintptr(0x70000)
		cred1BufAddr   = uintptr(0x80000)
		pkg2BufAddr    = uintptr(0x71000)
		cred2BufAddr   = uintptr(0x81000)
	)
	r := newBufferReader()

	entry := make([]byte, credentialEntryReadSize)
	stampCredentialEntry(entry, 0, 2 /*Kerberos*/, primary1Addr)
	r.put(entryAddr, entry)

	pkg1 := utf16LEBytes("Kerberos")
	cipher1 := []byte{0x11, 0x22}
	enc1 := makePrimaryEnc(pkg1BufAddr, cred1BufAddr, uint16(len(pkg1)), uint16(len(cipher1)))
	binary.LittleEndian.PutUint64(enc1[0:8], uint64(primary2Addr))
	r.put(primary1Addr, enc1)
	r.put(pkg1BufAddr, pkg1)
	r.put(cred1BufAddr, cipher1)

	pkg2 := utf16LEBytes("Kerberos-Newer-Keys")
	cipher2 := []byte{0x33, 0x44, 0x55}
	enc2 := makePrimaryEnc(pkg2BufAddr, cred2BufAddr, uint16(len(pkg2)), uint16(len(cipher2)))
	r.put(primary2Addr, enc2)
	r.put(pkg2BufAddr, pkg2)
	r.put(cred2BufAddr, cipher2)

	entries, err := walkCredentialList(r, entryAddr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.AuthPackageName != "Kerberos" {
		t.Errorf("AuthPackage = %q, want Kerberos", e.AuthPackageName)
	}
	if e.Primary == nil {
		t.Fatal("Primary is nil")
	}
	if len(e.PrimaryEntries) != 2 {
		t.Fatalf("PrimaryEntries = %d, want 2", len(e.PrimaryEntries))
	}
	if string(e.PrimaryEntries[0].EncryptedBytes) != string(cipher1) {
		t.Error("PrimaryEntries[0] cipher mismatch")
	}
	if string(e.PrimaryEntries[1].EncryptedBytes) != string(cipher2) {
		t.Error("PrimaryEntries[1] cipher mismatch")
	}
}
