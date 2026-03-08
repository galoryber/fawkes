// ticket_serialize.go contains Kerberos ticket serialization functions for
// kirbi (KRB-CRED) and ccache format output, plus session key generation.

package commands

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func ticketGenerateSessionKey(etypeID int32) (types.EncryptionKey, error) {
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	keySize := et.GetKeyByteSize()
	keyValue := make([]byte, keySize)
	if _, err := rand.Read(keyValue); err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyValue,
	}, nil
}

// ticketToKirbi creates a KRB-CRED (kirbi) format from a forged ticket.
// KRBCred has no Marshal() method in gokrb5, so we construct ASN.1 manually.
func ticketToKirbi(ticket messages.Ticket, sessionKey types.EncryptionKey, username, realm string, sname types.PrincipalName, flags asn1.BitString, authTime, endTime, renewTill time.Time) ([]byte, error) {
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKrbCredPart containing ticket info
	credInfo := messages.KrbCredInfo{
		Key:       sessionKey,
		PRealm:    realm,
		PName:     types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{username}},
		Flags:     flags,
		AuthTime:  authTime,
		StartTime: authTime,
		EndTime:   endTime,
		RenewTill: renewTill,
		SRealm:    realm,
		SName:     sname,
	}

	encCredPart := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{credInfo},
	}

	encCredPartBytes, err := asn1.Marshal(encCredPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncKrbCredPart: %w", err)
	}
	encCredPartBytes = asn1tools.AddASNAppTag(encCredPartBytes, asnAppTag.EncKrbCredPart)

	// KRB-CRED EncPart is "encrypted" with no encryption (etype 0, cipher = plaintext)
	// This is how Mimikatz and Rubeus generate kirbi files
	encPart := types.EncryptedData{
		EType:  0,
		Cipher: encCredPartBytes,
	}

	// Build KRBCred ASN.1 manually
	// KRB-CRED ::= [APPLICATION 22] SEQUENCE {
	//   pvno    [0] INTEGER,
	//   msg-type [1] INTEGER,
	//   tickets  [2] SEQUENCE OF Ticket,
	//   enc-part [3] EncryptedData
	// }
	type krbCredASN1 struct {
		PVNO    int                 `asn1:"explicit,tag:0"`
		MsgType int                 `asn1:"explicit,tag:1"`
		Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
		EncPart types.EncryptedData `asn1:"explicit,tag:3"`
	}

	// Wrap ticket bytes in SEQUENCE
	ticketsSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ticketBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tickets sequence: %w", err)
	}

	krbCred := krbCredASN1{
		PVNO:    iana.PVNO,
		MsgType: 22, // KRB_CRED
		Tickets: asn1.RawValue{FullBytes: ticketsSeq},
		EncPart: encPart,
	}

	krbCredBytes, err := asn1.Marshal(krbCred)
	if err != nil {
		return nil, fmt.Errorf("marshal KRBCred: %w", err)
	}
	krbCredBytes = asn1tools.AddASNAppTag(krbCredBytes, asnAppTag.KRBCred)

	return krbCredBytes, nil
}

// ticketToCCache creates a ccache file (version 4) from a forged ticket.
func ticketToCCache(ticketBytes []byte, sessionKey types.EncryptionKey, username, realm string, sname types.PrincipalName, flags asn1.BitString, authTime, endTime, renewTill time.Time) []byte {
	var buf []byte

	// File format version: 0x0504 (version 4)
	buf = append(buf, 0x05, 0x04)

	// Header length (v4): 12 bytes (one tag)
	headerLen := uint16(12)
	buf = binary.BigEndian.AppendUint16(buf, headerLen)
	// Header tag: deltatime (tag=1, length=8, value=0)
	buf = binary.BigEndian.AppendUint16(buf, 1) // tag
	buf = binary.BigEndian.AppendUint16(buf, 8) // length
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0)  // 8 bytes of zero

	// Default principal
	buf = ccacheWritePrincipal(buf, realm, []string{username})

	// Credential entry
	// Client principal
	buf = ccacheWritePrincipal(buf, realm, []string{username})
	// Server principal
	buf = ccacheWritePrincipal(buf, realm, sname.NameString)

	// Keyblock
	buf = binary.BigEndian.AppendUint16(buf, uint16(sessionKey.KeyType))
	buf = binary.BigEndian.AppendUint16(buf, 0) // etype (v4 only)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sessionKey.KeyValue)))
	buf = append(buf, sessionKey.KeyValue...)

	// Times
	buf = binary.BigEndian.AppendUint32(buf, uint32(authTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(authTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(endTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(renewTill.Unix()))

	// is_skey (uint8)
	buf = append(buf, 0)

	// Ticket flags (uint32, big-endian)
	flagVal := uint32(0)
	if len(flags.Bytes) >= 4 {
		flagVal = binary.BigEndian.Uint32(flags.Bytes)
	}
	buf = binary.BigEndian.AppendUint32(buf, flagVal)

	// Addresses (count=0)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// AuthData (count=0)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// Ticket data
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ticketBytes)))
	buf = append(buf, ticketBytes...)

	// Second ticket (empty)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

func ccacheWritePrincipal(buf []byte, realm string, components []string) []byte {
	// name_type (uint32)
	buf = binary.BigEndian.AppendUint32(buf, 1) // KRB_NT_PRINCIPAL
	// num_components (uint32)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(components)))
	// realm
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(realm)))
	buf = append(buf, []byte(realm)...)
	// components
	for _, c := range components {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(c)))
		buf = append(buf, []byte(c)...)
	}
	return buf
}
