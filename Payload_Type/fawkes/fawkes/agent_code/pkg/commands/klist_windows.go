//go:build windows
// +build windows

package commands

import (
	"fmt"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	secur32KL                      = windows.NewLazySystemDLL("secur32.dll")
	procLsaConnectUntrusted        = secur32KL.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPkg = secur32KL.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPkg   = secur32KL.NewProc("LsaCallAuthenticationPackage")
	procLsaDeregisterLogonProcess  = secur32KL.NewProc("LsaDeregisterLogonProcess")
	procLsaFreeReturnBuffer        = secur32KL.NewProc("LsaFreeReturnBuffer")
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
	_pad          uint32 // alignment padding on amd64
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
	_pad        uint32 // align to 8-byte boundary for UNICODE_STRING
	ServerName  unicodeStringKL
	RealmName   unicodeStringKL
}

// kerbRetrieveTktRequest matches KERB_RETRIEVE_TKT_REQUEST on amd64
type kerbRetrieveTktRequest struct {
	MessageType       uint32
	LogonIdLow        uint32
	LogonIdHigh       int32
	_pad              uint32          // align TargetName
	TargetName        unicodeStringKL // 16 bytes
	TicketFlags       uint32
	CacheOptions      uint32
	EncryptionType    int32
	_pad2             uint32   // align CredentialsHandle
	CredentialsHandle [16]byte // SecHandle (two uintptrs)
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
