package commands

import (
	"encoding/binary"
	"strings"
	"testing"
)

// stampCredentialListEntry writes a 32-byte CREDENTIAL_LIST entry header
// (Flink at +0, AuthPkgId at +8, _pad at +12, PrimaryCredentials_data at +16,
// trailing 8 bytes left zero). Buffer must be at least credentialListEntryReadSize.
func stampCredentialListEntry(buf []byte, flink uintptr, authPkgID uint32, primaryPtr uintptr) {
	binary.LittleEndian.PutUint64(buf[0:8], uint64(flink))
	binary.LittleEndian.PutUint32(buf[8:12], authPkgID)
	// raw[12:16] = padding (left zero)
	binary.LittleEndian.PutUint64(buf[16:24], uint64(primaryPtr))
	// raw[24:32] = trailing slack (left zero) — present in our 32-byte read but not parsed
}

// makePrimaryEnc builds a 48-byte PRIMARY_CREDENTIAL_ENC envelope. Caller is
// responsible for registering the buffer-pointer pages on the test reader.
func makePrimaryEnc(userBuf, domainBuf, encBuf uintptr, userLenBytes, domainLenBytes, encLenBytes uint16) []byte {
	raw := make([]byte, primaryCredentialEncSize)
	stampUnicodeStringHeader(raw, primaryEncUserNameOff, userLenBytes, userBuf)
	stampUnicodeStringHeader(raw, primaryEncDomainOff, domainLenBytes, domainBuf)
	stampUnicodeStringHeader(raw, primaryEncEncryptedOff, encLenBytes, encBuf)
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
	// Encrypted ciphertext is binary; odd byte counts are legal (unlike UTF-16
	// strings which readLSAUnicodeString rejects).
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
	// Length=0 → returns nil/no-error with the on-the-wire address echoed back.
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 0, 0xDEAD0000)
	bytes, addr, length, err := readLSAUnicodeRawBytes(newBufferReader(), raw, 0, ciphertextSanityMax)
	if err != nil || bytes != nil || length != 0 || addr != 0xDEAD0000 {
		t.Errorf("Length=0: bytes=%v addr=0x%X length=%d err=%v; want nil/0xDEAD0000/0/nil", bytes, addr, length, err)
	}

	// Buffer=NULL → returns nil/no-error.
	stampUnicodeStringHeader(raw, 0, 16, 0)
	bytes, addr, length, err = readLSAUnicodeRawBytes(newBufferReader(), raw, 0, ciphertextSanityMax)
	if err != nil || bytes != nil || addr != 0 || length != 16 {
		t.Errorf("Buffer=0: bytes=%v addr=0x%X length=%d err=%v; want nil/0/16/nil", bytes, addr, length, err)
	}
}

func TestReadPrimaryCredentialEnc_FullEnvelope(t *testing.T) {
	const (
		envelopeAddr = uintptr(0x1000)
		userBufAddr  = uintptr(0x2000)
		domainBuf    = uintptr(0x3000)
		encBuf       = uintptr(0x4000)
	)
	user := utf16LEBytes("alice")
	domain := utf16LEBytes("CORP")
	cipher := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	r := newBufferReader()
	r.put(userBufAddr, user)
	r.put(domainBuf, domain)
	r.put(encBuf, cipher)
	r.put(envelopeAddr, makePrimaryEnc(userBufAddr, domainBuf, encBuf, uint16(len(user)), uint16(len(domain)), uint16(len(cipher))))

	p, err := readPrimaryCredentialEnc(r, envelopeAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.UserName != "alice" {
		t.Errorf("UserName = %q, want alice", p.UserName)
	}
	if p.Domain != "CORP" {
		t.Errorf("Domain = %q, want CORP", p.Domain)
	}
	if p.EncryptedAddress != encBuf {
		t.Errorf("EncryptedAddress = 0x%X, want 0x%X", p.EncryptedAddress, encBuf)
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
		envelopeAddr = uintptr(0x1000)
		userBufAddr  = uintptr(0x2000)
		domainBuf    = uintptr(0x3000) // intentionally NOT registered → remote read fails
		encBuf       = uintptr(0x4000)
	)
	user := utf16LEBytes("bob")
	cipher := []byte{0x11, 0x22}
	r := newBufferReader()
	r.put(userBufAddr, user)
	r.put(encBuf, cipher)
	r.put(envelopeAddr, makePrimaryEnc(userBufAddr, domainBuf, encBuf, uint16(len(user)), 8, uint16(len(cipher))))

	p, err := readPrimaryCredentialEnc(r, envelopeAddr)
	if err != nil {
		t.Fatalf("unexpected envelope error: %v", err)
	}
	if p.UserName != "bob" {
		t.Errorf("UserName = %q, want bob", p.UserName)
	}
	if p.Domain != "" {
		t.Errorf("Domain = %q, want empty (Domain remote read failed)", p.Domain)
	}
	if string(p.EncryptedBytes) != string(cipher) {
		t.Errorf("EncryptedBytes = %v, want %v", p.EncryptedBytes, cipher)
	}
	if len(p.ParseErrors) != 1 || !strings.Contains(p.ParseErrors[0], "Domain") {
		t.Errorf("expected one Domain ParseError, got %v", p.ParseErrors)
	}
}

func TestReadPrimaryCredentialEnc_ZeroAddr(t *testing.T) {
	_, err := readPrimaryCredentialEnc(newBufferReader(), 0)
	if err == nil || !strings.Contains(err.Error(), "zero PrimaryCredentials_data") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadPrimaryCredentialEnc_EnvelopeReadFails(t *testing.T) {
	// Envelope address not registered in the reader → 48-byte read fails fatally.
	_, err := readPrimaryCredentialEnc(newBufferReader(), 0xDEAD)
	if err == nil || !strings.Contains(err.Error(), "read PRIMARY_CREDENTIAL_ENC") {
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
		entryAddr   = uintptr(0x10000)
		primaryAddr = uintptr(0x20000)
		userBufAddr = uintptr(0x30000)
		encBufAddr  = uintptr(0x40000)
	)
	user := utf16LEBytes("svc")
	cipher := []byte{0xAA, 0xBB}
	r := newBufferReader()

	entry := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(entry, 0, 0 /*MSV1_0*/, primaryAddr)
	r.put(entryAddr, entry)
	r.put(primaryAddr, makePrimaryEnc(userBufAddr, 0, encBufAddr, uint16(len(user)), 0, uint16(len(cipher))))
	r.put(userBufAddr, user)
	r.put(encBufAddr, cipher)

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
	if e.PrimaryCredentialsDataPtr != primaryAddr {
		t.Errorf("PrimaryCredentialsDataPtr = 0x%X, want 0x%X", e.PrimaryCredentialsDataPtr, primaryAddr)
	}
	if e.Primary == nil {
		t.Fatal("Primary is nil")
	}
	if e.Primary.UserName != "svc" {
		t.Errorf("Primary.UserName = %q, want svc", e.Primary.UserName)
	}
	if string(e.Primary.EncryptedBytes) != string(cipher) {
		t.Errorf("Primary.EncryptedBytes = %v, want %v", e.Primary.EncryptedBytes, cipher)
	}
	if e.PrimaryReadErr != "" {
		t.Errorf("unexpected PrimaryReadErr: %q", e.PrimaryReadErr)
	}
}

func TestWalkCredentialList_ChainTerminatesOnNullFlink(t *testing.T) {
	const (
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()
	e1 := make([]byte, credentialListEntryReadSize)
	e2 := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(e1, entry2Addr, 2 /*Kerberos*/, 0 /*no primary data*/)
	stampCredentialListEntry(e2, 0 /*terminator*/, 0 /*MSV1_0*/, 0)
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, entry1Addr, 16)
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
	if entries[0].Primary != nil {
		t.Errorf("entry[0].Primary should be nil (zero data ptr), got %+v", entries[0].Primary)
	}
}

func TestWalkCredentialList_CycleDetected(t *testing.T) {
	const (
		entry1Addr = uintptr(0x10000)
		entry2Addr = uintptr(0x11000)
	)
	r := newBufferReader()
	e1 := make([]byte, credentialListEntryReadSize)
	e2 := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(e1, entry2Addr, 0, 0)
	stampCredentialListEntry(e2, entry1Addr, 0, 0) // points back to entry1 → cycle
	r.put(entry1Addr, e1)
	r.put(entry2Addr, e2)

	entries, err := walkCredentialList(r, entry1Addr, 16)
	if err == nil || !strings.Contains(err.Error(), "cycle detected") {
		t.Errorf("expected cycle-detected error, got %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries before cycle detect, want 2", len(entries))
	}
}

func TestWalkCredentialList_SafetyCap(t *testing.T) {
	// 5-entry chain + maxEntries=3 → cap fires after 3.
	addrs := []uintptr{0x10000, 0x11000, 0x12000, 0x13000, 0x14000}
	r := newBufferReader()
	for i, a := range addrs {
		e := make([]byte, credentialListEntryReadSize)
		var flink uintptr
		if i+1 < len(addrs) {
			flink = addrs[i+1]
		}
		stampCredentialListEntry(e, flink, 0, 0)
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

func TestWalkCredentialList_NodeReadFailure(t *testing.T) {
	// Address 0xBAD intentionally not registered.
	entries, err := walkCredentialList(newBufferReader(), 0xBAD, 16)
	if err == nil || !strings.Contains(err.Error(), "read credential entry") {
		t.Errorf("expected read failure, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries before read failure, got %d", len(entries))
	}
}

func TestWalkCredentialList_PrimaryReadFailureRecorded(t *testing.T) {
	// Entry walks fine but PrimaryCredentialsDataPtr → unregistered page → read fails.
	const entryAddr = uintptr(0x10000)
	r := newBufferReader()
	e := make([]byte, credentialListEntryReadSize)
	stampCredentialListEntry(e, 0, 3 /*WDigest*/, 0xBAD)
	r.put(entryAddr, e)

	entries, err := walkCredentialList(r, entryAddr, 16)
	if err != nil {
		t.Fatalf("entry walk should succeed, got %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Primary != nil {
		t.Errorf("Primary should be nil on read failure, got %+v", entries[0].Primary)
	}
	if entries[0].PrimaryReadErr == "" {
		t.Errorf("PrimaryReadErr should be populated on read failure")
	}
}
