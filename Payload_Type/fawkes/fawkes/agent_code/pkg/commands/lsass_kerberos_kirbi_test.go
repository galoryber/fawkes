package commands

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestKirbiInt_Zero(t *testing.T) {
	got := kirbiInt(0)
	// ASN.1 INTEGER 0 = 02 01 00
	want := []byte{0x02, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("kirbiInt(0) = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestKirbiInt_SmallPositive(t *testing.T) {
	got := kirbiInt(5)
	// ASN.1 INTEGER 5 = 02 01 05
	want := []byte{0x02, 0x01, 0x05}
	if !bytes.Equal(got, want) {
		t.Errorf("kirbiInt(5) = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestKirbiInt_22(t *testing.T) {
	got := kirbiInt(22)
	// KRB-CRED msg-type = 22 = 0x16
	want := []byte{0x02, 0x01, 0x16}
	if !bytes.Equal(got, want) {
		t.Errorf("kirbiInt(22) = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestKirbiInt_128(t *testing.T) {
	got := kirbiInt(128)
	// 128 = 0x80, needs leading 0 to avoid sign bit
	// 02 02 00 80
	want := []byte{0x02, 0x02, 0x00, 0x80}
	if !bytes.Equal(got, want) {
		t.Errorf("kirbiInt(128) = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestKirbiInt_256(t *testing.T) {
	got := kirbiInt(256)
	// 256 = 0x0100
	want := []byte{0x02, 0x02, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("kirbiInt(256) = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestKirbiGeneralString(t *testing.T) {
	got := kirbiGeneralString("REALM.COM")
	// GeneralString tag=0x1B
	if got[0] != 0x1B {
		t.Errorf("kirbiGeneralString tag = 0x%02x, want 0x1B", got[0])
	}
	if got[1] != 9 {
		t.Errorf("kirbiGeneralString length = %d, want 9", got[1])
	}
	if string(got[2:]) != "REALM.COM" {
		t.Errorf("kirbiGeneralString content = %q, want %q", string(got[2:]), "REALM.COM")
	}
}

func TestKirbiGeneralString_Empty(t *testing.T) {
	got := kirbiGeneralString("")
	if len(got) != 2 || got[0] != 0x1B || got[1] != 0 {
		t.Errorf("kirbiGeneralString(\"\") = %s, want 1b00", hex.EncodeToString(got))
	}
}

func TestKirbiTime(t *testing.T) {
	ts := time.Date(2026, 6, 4, 15, 30, 45, 0, time.UTC)
	got := kirbiTime(ts)
	// GeneralizedTime tag=0x18, "20260604153045Z"
	if got[0] != 0x18 {
		t.Errorf("kirbiTime tag = 0x%02x, want 0x18", got[0])
	}
	content := string(got[2:])
	want := "20260604153045Z"
	if content != want {
		t.Errorf("kirbiTime content = %q, want %q", content, want)
	}
}

func TestKirbiTime_NonUTC(t *testing.T) {
	loc := time.FixedZone("EST", -5*3600)
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, loc)
	got := kirbiTime(ts)
	content := string(got[2:])
	// Should convert to UTC: 15:00:00
	want := "20260115150000Z"
	if content != want {
		t.Errorf("kirbiTime non-UTC = %q, want %q", content, want)
	}
}

func TestKirbiBitString32(t *testing.T) {
	got := kirbiBitString32(0x50800000) // forwardable + renewable + initial
	if got[0] != 0x03 {
		t.Errorf("kirbiBitString32 tag = 0x%02x, want 0x03", got[0])
	}
	if got[1] != 5 { // 1 unused-bits byte + 4 data bytes
		t.Errorf("kirbiBitString32 length = %d, want 5", got[1])
	}
	if got[2] != 0 { // 0 unused bits
		t.Errorf("kirbiBitString32 unused bits = %d, want 0", got[2])
	}
	// Flags in big-endian: 0x50800000
	if got[3] != 0x50 || got[4] != 0x80 || got[5] != 0x00 || got[6] != 0x00 {
		t.Errorf("kirbiBitString32 data = %s, want 50800000", hex.EncodeToString(got[3:7]))
	}
}

func TestKirbiBitString32_Zero(t *testing.T) {
	got := kirbiBitString32(0)
	if got[3] != 0 || got[4] != 0 || got[5] != 0 || got[6] != 0 {
		t.Errorf("kirbiBitString32(0) data = %s, want 00000000", hex.EncodeToString(got[3:7]))
	}
}

func TestKirbiExplicit(t *testing.T) {
	inner := []byte{0x02, 0x01, 0x05} // INTEGER 5
	got := kirbiExplicit(0, inner)
	// [0] EXPLICIT = tag 0xA0
	if got[0] != 0xA0 {
		t.Errorf("kirbiExplicit(0) tag = 0x%02x, want 0xA0", got[0])
	}
	if got[1] != 3 {
		t.Errorf("kirbiExplicit length = %d, want 3", got[1])
	}
	if !bytes.Equal(got[2:], inner) {
		t.Errorf("kirbiExplicit content mismatch")
	}
}

func TestKirbiExplicit_Tag3(t *testing.T) {
	inner := []byte{0x30, 0x00} // empty SEQUENCE
	got := kirbiExplicit(3, inner)
	if got[0] != 0xA3 {
		t.Errorf("kirbiExplicit(3) tag = 0x%02x, want 0xA3", got[0])
	}
}

func TestKirbiApp(t *testing.T) {
	inner := []byte{0x30, 0x00}
	got := kirbiApp(22, inner)
	// APPLICATION 22 = 0x60 | 22 = 0x76
	if got[0] != 0x76 {
		t.Errorf("kirbiApp(22) tag = 0x%02x, want 0x76", got[0])
	}
}

func TestKirbiApp_29(t *testing.T) {
	inner := []byte{0x30, 0x00}
	got := kirbiApp(29, inner)
	// APPLICATION 29 = 0x60 | 29 = 0x7D
	if got[0] != 0x7D {
		t.Errorf("kirbiApp(29) tag = 0x%02x, want 0x7D", got[0])
	}
}

func TestKirbiSplitName_Simple(t *testing.T) {
	got := kirbiSplitName("krbtgt/REALM.COM")
	if len(got) != 2 || got[0] != "krbtgt" || got[1] != "REALM.COM" {
		t.Errorf("kirbiSplitName(krbtgt/REALM.COM) = %v, want [krbtgt, REALM.COM]", got)
	}
}

func TestKirbiSplitName_NoSlash(t *testing.T) {
	got := kirbiSplitName("Administrator")
	if len(got) != 1 || got[0] != "Administrator" {
		t.Errorf("kirbiSplitName(Administrator) = %v, want [Administrator]", got)
	}
}

func TestKirbiSplitName_MultiComponent(t *testing.T) {
	got := kirbiSplitName("HTTP/web.corp.com/corp.com")
	if len(got) != 3 {
		t.Fatalf("kirbiSplitName 3-component = %v, want 3 parts", got)
	}
	if got[0] != "HTTP" || got[1] != "web.corp.com" || got[2] != "corp.com" {
		t.Errorf("kirbiSplitName = %v", got)
	}
}

func TestKirbiPrincipalName_KrbtgtService(t *testing.T) {
	got := kirbiPrincipalName(2, "krbtgt/REALM.COM")
	// Should produce SEQUENCE { [0] INTEGER 2, [1] SEQUENCE { GeneralString "krbtgt", GeneralString "REALM.COM" } }
	if got[0] != 0x30 { // SEQUENCE
		t.Errorf("principal name not a SEQUENCE, tag = 0x%02x", got[0])
	}
	// Verify the name-type [0] INTEGER 2 is present
	if !bytes.Contains(got, []byte{0xA0}) {
		t.Error("missing [0] explicit tag for name-type")
	}
	// Verify both name strings are present
	if !bytes.Contains(got, []byte("krbtgt")) {
		t.Error("missing 'krbtgt' in principal name")
	}
	if !bytes.Contains(got, []byte("REALM.COM")) {
		t.Error("missing 'REALM.COM' in principal name")
	}
}

func TestKirbiEncryptedData_Etype0(t *testing.T) {
	plaintext := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	got := kirbiEncryptedData(0, plaintext)
	// SEQUENCE { [0] INTEGER 0, [2] OCTET STRING { plaintext } }
	if got[0] != 0x30 {
		t.Errorf("encrypted data not SEQUENCE, tag = 0x%02x", got[0])
	}
	// Should contain etype 0
	etypeBytes := kirbiExplicit(0, kirbiInt(0))
	if !bytes.Contains(got, etypeBytes) {
		t.Error("encrypted data missing etype [0] INTEGER 0")
	}
	// Should contain the plaintext in an octet string
	if !bytes.Contains(got, plaintext) {
		t.Error("encrypted data missing plaintext content")
	}
}

func TestKirbiCredInfo_FullTicket(t *testing.T) {
	ticket := kerbTicket{
		ServiceName:  "krbtgt/CONTOSO.COM",
		ClientName:   "Administrator",
		DomainName:   "CONTOSO.COM",
		TargetDomain: "CONTOSO.COM",
		KeyType:      23,
		KeyBytes:     []byte{0x01, 0x02, 0x03, 0x04},
		TicketFlags:  0x50800000,
		StartTime:    time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		EndTime:      time.Date(2026, 6, 4, 22, 0, 0, 0, time.UTC),
		RenewUntil:   time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
	}

	got := kirbiCredInfo(ticket)
	if got[0] != 0x30 {
		t.Errorf("credInfo not SEQUENCE, tag = 0x%02x", got[0])
	}

	// Verify key components are present
	if !bytes.Contains(got, []byte("CONTOSO.COM")) {
		t.Error("credInfo missing domain name")
	}
	if !bytes.Contains(got, []byte("Administrator")) {
		t.Error("credInfo missing client name")
	}
	if !bytes.Contains(got, []byte("krbtgt")) {
		t.Error("credInfo missing service name")
	}
	if !bytes.Contains(got, ticket.KeyBytes) {
		t.Error("credInfo missing session key bytes")
	}
}

func TestKirbiCredInfo_MinimalTicket(t *testing.T) {
	ticket := kerbTicket{
		KeyType:  17,
		KeyBytes: []byte{0xAA},
	}
	got := kirbiCredInfo(ticket)
	if got[0] != 0x30 {
		t.Errorf("credInfo not SEQUENCE, tag = 0x%02x", got[0])
	}
	// Should still have [0] EncryptionKey
	if !bytes.Contains(got, []byte{0xA0}) {
		t.Error("credInfo missing [0] EncryptionKey tag")
	}
}

func TestBuildKirbi_Structure(t *testing.T) {
	ticket := kerbTicket{
		ServiceName:  "krbtgt/REALM.COM",
		ClientName:   "user",
		DomainName:   "REALM.COM",
		KeyType:      23,
		KeyBytes:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		TicketFlags:  0x40E10000,
		StartTime:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EndTime:      time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		TicketBytes:  []byte{0x61, 0x03, 0x02, 0x01, 0x05}, // fake APPLICATION 1 Ticket
	}

	got, err := buildKirbi(ticket)
	if err != nil {
		t.Fatalf("buildKirbi error: %v", err)
	}

	// Top-level: APPLICATION 22 = tag 0x76
	if got[0] != 0x76 {
		t.Errorf("kirbi top-level tag = 0x%02x, want 0x76 (APPLICATION 22)", got[0])
	}

	// Should contain pvno=5 and msg-type=22
	pvno := kirbiExplicit(0, kirbiInt(5))
	if !bytes.Contains(got, pvno) {
		t.Error("kirbi missing pvno [0] INTEGER 5")
	}

	msgType := kirbiExplicit(1, kirbiInt(22))
	if !bytes.Contains(got, msgType) {
		t.Error("kirbi missing msg-type [1] INTEGER 22")
	}

	// Should contain the raw ticket bytes
	if !bytes.Contains(got, ticket.TicketBytes) {
		t.Error("kirbi missing raw ticket bytes")
	}

	// Should contain etype=0 for unencrypted KRB-CRED
	etype0 := kirbiInt(0)
	if !bytes.Contains(got, etype0) {
		t.Error("kirbi missing etype=0 for unencrypted enc-part")
	}
}

func TestBuildKirbi_EmptyTicketBytes(t *testing.T) {
	ticket := kerbTicket{
		KeyType:  23,
		KeyBytes: []byte{0x01},
	}
	_, err := buildKirbi(ticket)
	if err == nil {
		t.Error("buildKirbi with empty TicketBytes should return error")
	}
}

func TestDerWrap_ShortLength(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03}
	got := derWrap(0x30, content)
	if got[0] != 0x30 || got[1] != 3 {
		t.Errorf("derWrap short = %s, want 30 03...", hex.EncodeToString(got[:2]))
	}
	if !bytes.Equal(got[2:], content) {
		t.Error("derWrap content mismatch")
	}
}

func TestDerWrap_LongLength(t *testing.T) {
	content := make([]byte, 200)
	got := derWrap(0x30, content)
	// Length 200 > 127, uses 0x81 prefix: 30 81 C8
	if got[0] != 0x30 || got[1] != 0x81 || got[2] != 0xC8 {
		t.Errorf("derWrap long = %s, want 30 81 c8...", hex.EncodeToString(got[:3]))
	}
}

func TestDerSequence_MultipleElements(t *testing.T) {
	a := kirbiInt(1)
	b := kirbiInt(2)
	got := derSequence(a, b)
	if got[0] != 0x30 {
		t.Errorf("derSequence tag = 0x%02x, want 0x30", got[0])
	}
	expectedLen := len(a) + len(b)
	if int(got[1]) != expectedLen {
		t.Errorf("derSequence length = %d, want %d", got[1], expectedLen)
	}
}

func TestDerOctetString(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	got := derOctetString(data)
	if got[0] != 0x04 || got[1] != 4 {
		t.Errorf("derOctetString header = %s, want 04 04", hex.EncodeToString(got[:2]))
	}
	if !bytes.Equal(got[2:], data) {
		t.Error("derOctetString content mismatch")
	}
}
