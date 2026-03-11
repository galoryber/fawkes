package commands

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// These tests cover ticket_serialize.go internal functions that aren't exercised
// by the end-to-end ticket command tests in ticket_test.go.

// --- ccacheWritePrincipal edge cases ---

func TestCcacheWritePrincipalExactSize(t *testing.T) {
	// Verify exact binary size for multi-component SPN
	buf := ccacheWritePrincipal(nil, "REALM.COM", []string{"krbtgt", "REALM.COM"})

	// name_type(4) + num_components(4) + realm_len(4) + "REALM.COM"(9)
	// + comp0_len(4) + "krbtgt"(6) + comp1_len(4) + "REALM.COM"(9) = 44
	if len(buf) != 44 {
		t.Errorf("total size = %d, want 44", len(buf))
	}

	numComp := binary.BigEndian.Uint32(buf[4:8])
	if numComp != 2 {
		t.Errorf("num_components = %d, want 2", numComp)
	}
}

func TestCcacheWritePrincipalAppendsToExisting(t *testing.T) {
	existing := []byte{0xDE, 0xAD}
	buf := ccacheWritePrincipal(existing, "R", []string{"u"})

	if buf[0] != 0xDE || buf[1] != 0xAD {
		t.Error("existing data should be preserved at the start")
	}

	nameType := binary.BigEndian.Uint32(buf[2:6])
	if nameType != 1 {
		t.Errorf("name_type after prefix = %d, want 1", nameType)
	}
}

// --- ticketToCCache binary format verification ---

func TestTicketToCCacheKeyblock(t *testing.T) {
	keyValue := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.RC4_HMAC, // 23
		KeyValue: keyValue,
	}
	sname := types.PrincipalName{NameString: []string{"krbtgt", "R.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()

	ccache := ticketToCCache([]byte{0x01}, sessionKey, "u", "R.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))

	// Search for keyblock: etype(2) + etype_v4(2) + key_len(2) + key_value
	for i := 0; i <= len(ccache)-6-16; i++ {
		etype := binary.BigEndian.Uint16(ccache[i : i+2])
		if etype == 23 {
			keyLen := binary.BigEndian.Uint16(ccache[i+4 : i+6])
			if keyLen == 16 {
				for j := 0; j < 16; j++ {
					if ccache[i+6+j] != keyValue[j] {
						t.Errorf("key byte %d: got 0x%02X, want 0x%02X", j, ccache[i+6+j], keyValue[j])
					}
				}
				return
			}
		}
	}
	t.Error("keyblock not found in ccache output")
}

func TestTicketToCCacheTimestampSequence(t *testing.T) {
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: make([]byte, 16),
	}
	sname := types.PrincipalName{NameString: []string{"krbtgt", "X.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}

	authTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	renewTime := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)

	ccache := ticketToCCache([]byte{0x01}, sessionKey, "u", "X.COM", sname, flags,
		authTime, endTime, renewTime)

	authUnix := uint32(authTime.Unix())
	endUnix := uint32(endTime.Unix())
	renewUnix := uint32(renewTime.Unix())

	// Timestamps appear as 4 consecutive uint32 BE values:
	// authtime, starttime (=authtime), endtime, renewtill
	found := false
	for i := 0; i <= len(ccache)-16; i++ {
		t1 := binary.BigEndian.Uint32(ccache[i : i+4])
		t2 := binary.BigEndian.Uint32(ccache[i+4 : i+8])
		t3 := binary.BigEndian.Uint32(ccache[i+8 : i+12])
		t4 := binary.BigEndian.Uint32(ccache[i+12 : i+16])
		if t1 == authUnix && t2 == authUnix && t3 == endUnix && t4 == renewUnix {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected timestamp sequence (authtime, starttime, endtime, renewtill) not found")
	}
}

func TestTicketToCCacheFlags(t *testing.T) {
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: make([]byte, 16),
	}
	sname := types.PrincipalName{NameString: []string{"krbtgt", "F.COM"}}
	flagBytes := []byte{0x50, 0x80, 0x00, 0x10}
	flags := asn1.BitString{Bytes: flagBytes, BitLength: 32}
	t0 := time.Now()

	ccache := ticketToCCache([]byte{0x01}, sessionKey, "u", "F.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))

	flagVal := binary.BigEndian.Uint32(flagBytes)
	found := false
	for i := 0; i <= len(ccache)-4; i++ {
		v := binary.BigEndian.Uint32(ccache[i : i+4])
		if v == flagVal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flags 0x%08X not found in ccache", flagVal)
	}
}

func TestTicketToCCacheShortFlags(t *testing.T) {
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.RC4_HMAC,
		KeyValue: make([]byte, 16),
	}
	sname := types.PrincipalName{NameString: []string{"k"}}
	flags := asn1.BitString{Bytes: []byte{0x50}, BitLength: 8}
	t0 := time.Now()

	// Should not panic with short flags (< 4 bytes)
	ccache := ticketToCCache([]byte{0x01}, sessionKey, "u", "R", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))

	if ccache[0] != 0x05 || ccache[1] != 0x04 {
		t.Errorf("version = 0x%02X%02X, want 0x0504", ccache[0], ccache[1])
	}
}

func TestTicketToCCacheContainsTicketData(t *testing.T) {
	ticketBytes := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.RC4_HMAC,
		KeyValue: make([]byte, 16),
	}
	sname := types.PrincipalName{NameString: []string{"krbtgt", "T.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()

	ccache := ticketToCCache(ticketBytes, sessionKey, "u", "T.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))

	found := false
	for i := 0; i <= len(ccache)-len(ticketBytes); i++ {
		match := true
		for j := range ticketBytes {
			if ccache[i+j] != ticketBytes[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			if i >= 4 {
				embedLen := binary.BigEndian.Uint32(ccache[i-4 : i])
				if embedLen != uint32(len(ticketBytes)) {
					t.Errorf("ticket length prefix = %d, want %d", embedLen, len(ticketBytes))
				}
			}
			break
		}
	}
	if !found {
		t.Error("ticket bytes not found in ccache output")
	}
}

// --- ticketToKirbi ASN.1 structure tests ---

func TestTicketToKirbiAppTag(t *testing.T) {
	sessionKey, _ := ticketGenerateSessionKey(etypeID.AES256_CTS_HMAC_SHA1_96)
	sname := types.PrincipalName{NameString: []string{"krbtgt", "EXAMPLE.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x50, 0x80, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()
	ticket := testBuildTicket("EXAMPLE.COM", sname, sessionKey)

	kirbi, err := ticketToKirbi(ticket, sessionKey, "admin", "EXAMPLE.COM", sname, flags,
		t0, t0.Add(10*time.Hour), t0.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("ticketToKirbi error: %v", err)
	}

	if len(kirbi) == 0 {
		t.Fatal("kirbi output is empty")
	}

	// KRB-CRED APPLICATION 22 tag: 0x76 = 0x60 | 22
	if kirbi[0] != 0x76 {
		t.Errorf("first byte = 0x%02X, want 0x76 (APPLICATION 22)", kirbi[0])
	}
}

func TestTicketToKirbiContainsPVNO(t *testing.T) {
	sessionKey, _ := ticketGenerateSessionKey(etypeID.RC4_HMAC)
	sname := types.PrincipalName{NameString: []string{"krbtgt", "T.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()
	ticket := testBuildTicket("T.COM", sname, sessionKey)

	kirbi, err := ticketToKirbi(ticket, sessionKey, "u", "T.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("ticketToKirbi error: %v", err)
	}

	// ASN.1 INTEGER 5 = 0x02 0x01 0x05
	for i := 0; i <= len(kirbi)-3; i++ {
		if kirbi[i] == 0x02 && kirbi[i+1] == 0x01 && kirbi[i+2] == 0x05 {
			return
		}
	}
	t.Error("PVNO (5) not found in kirbi output")
}

func TestTicketToKirbiContainsMsgType22(t *testing.T) {
	sessionKey, _ := ticketGenerateSessionKey(etypeID.RC4_HMAC)
	sname := types.PrincipalName{NameString: []string{"krbtgt", "M.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()
	ticket := testBuildTicket("M.COM", sname, sessionKey)

	kirbi, err := ticketToKirbi(ticket, sessionKey, "u", "M.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("ticketToKirbi error: %v", err)
	}

	// ASN.1 INTEGER 22 = 0x02 0x01 0x16
	for i := 0; i <= len(kirbi)-3; i++ {
		if kirbi[i] == 0x02 && kirbi[i+1] == 0x01 && kirbi[i+2] == 0x16 {
			return
		}
	}
	t.Error("msg-type (22/KRB_CRED) not found in kirbi output")
}

func TestTicketToKirbiEncPartEtype0(t *testing.T) {
	// Kirbi files use etype 0 (no encryption) for the enc-part, like Mimikatz/Rubeus
	sessionKey, _ := ticketGenerateSessionKey(etypeID.AES256_CTS_HMAC_SHA1_96)
	sname := types.PrincipalName{NameString: []string{"krbtgt", "E.COM"}}
	flags := asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32}
	t0 := time.Now()
	ticket := testBuildTicket("E.COM", sname, sessionKey)

	kirbi, err := ticketToKirbi(ticket, sessionKey, "u", "E.COM", sname, flags,
		t0, t0.Add(time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("ticketToKirbi error: %v", err)
	}

	// ASN.1 INTEGER 0 = 0x02 0x01 0x00 — should appear for etype 0
	for i := 0; i <= len(kirbi)-3; i++ {
		if kirbi[i] == 0x02 && kirbi[i+1] == 0x01 && kirbi[i+2] == 0x00 {
			return
		}
	}
	t.Error("etype 0 (no encryption) not found in kirbi enc-part")
}

// testBuildTicket creates a minimal Kerberos Ticket for testing (local to this file)
func testBuildTicket(realm string, sname types.PrincipalName, key types.EncryptionKey) messages.Ticket {
	return messages.Ticket{
		TktVNO: 5,
		Realm:  realm,
		SName:  sname,
		EncPart: types.EncryptedData{
			EType:  key.KeyType,
			KVNO:   2,
			Cipher: make([]byte, 64),
		},
	}
}
