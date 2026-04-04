package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// parseEnumServiceStatusW parses the raw buffer from EnumServicesStatusW.
// Each ENUM_SERVICE_STATUSW entry is:
//   - 4 bytes: lpServiceName (pointer/offset into buffer)
//   - 4 bytes: lpDisplayName (pointer/offset into buffer)
//   - 7 x 4 bytes: SERVICE_STATUS (dwServiceType, dwCurrentState, dwControlsAccepted,
//     dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint)
//
// Total: 36 bytes per entry (on wire, pointers are 4 bytes each)
func parseEnumServiceStatusW(buf []byte, count uint32) []parsedService {
	// The RPC response uses a different layout than in-memory ENUM_SERVICE_STATUSW.
	// The buffer contains the SERVICE_STATUS structs followed by the string data.
	// Each entry in the buffer is:
	//   offset 0: service name offset (4 bytes, relative to buffer start)
	//   offset 4: display name offset (4 bytes, relative to buffer start)
	//   offset 8: ServiceStatus (7 x 4 = 28 bytes)
	// Total entry size: 36 bytes
	const entrySize = 36
	var services []parsedService

	for i := uint32(0); i < count; i++ {
		offset := i * entrySize
		if int(offset+entrySize) > len(buf) {
			break
		}

		svcNameOff := binary.LittleEndian.Uint32(buf[offset:])
		dispNameOff := binary.LittleEndian.Uint32(buf[offset+4:])
		svcType := binary.LittleEndian.Uint32(buf[offset+8:])
		curState := binary.LittleEndian.Uint32(buf[offset+12:])

		svcName := readUTF16StringFromBuf(buf, svcNameOff)
		dispName := readUTF16StringFromBuf(buf, dispNameOff)

		services = append(services, parsedService{
			serviceName:  svcName,
			displayName:  dispName,
			serviceType:  svcType,
			currentState: curState,
		})
	}

	return services
}

// readUTF16StringFromBuf reads a null-terminated UTF-16LE string from buf at the given byte offset.
func readUTF16StringFromBuf(buf []byte, offset uint32) string {
	if int(offset) >= len(buf) {
		return ""
	}
	var runes []uint16
	for i := int(offset); i+1 < len(buf); i += 2 {
		ch := binary.LittleEndian.Uint16(buf[i:])
		if ch == 0 {
			break
		}
		runes = append(runes, ch)
	}
	return string(utf16.Decode(runes))
}

func remoteSvcStateName(state uint32) string {
	switch state {
	case svcStateStopped:
		return "STOPPED"
	case svcStateStartPending:
		return "START_PENDING"
	case svcStateStopPending:
		return "STOP_PENDING"
	case svcStateRunning:
		return "RUNNING"
	case svcStateContinuePending:
		return "CONTINUE_PENDING"
	case svcStatePausePending:
		return "PAUSE_PENDING"
	case svcStatePaused:
		return "PAUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

func remoteSvcTypeName(t uint32) string {
	switch {
	case t&svcWin32OwnProcess != 0 && t&svcWin32ShareProcess != 0:
		return "WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS"
	case t&svcWin32OwnProcess != 0:
		return "WIN32_OWN_PROCESS"
	case t&svcWin32ShareProcess != 0:
		return "WIN32_SHARE_PROCESS"
	case t == 1:
		return "KERNEL_DRIVER"
	case t == 2:
		return "FILE_SYSTEM_DRIVER"
	default:
		return fmt.Sprintf("TYPE(0x%x)", t)
	}
}

func remoteSvcStartTypeName(t uint32) string {
	switch t {
	case svcStartBoot:
		return "BOOT_START"
	case svcStartSystem:
		return "SYSTEM_START"
	case svcStartAuto:
		return "AUTO_START"
	case svcStartDemand:
		return "DEMAND_START"
	case svcStartDisabled:
		return "DISABLED"
	default:
		return fmt.Sprintf("START_TYPE(%d)", t)
	}
}

func parseStartType(s string) uint32 {
	switch strings.ToLower(s) {
	case "auto":
		return svcStartAuto
	case "disabled":
		return svcStartDisabled
	case "demand", "manual", "":
		return svcStartDemand
	default:
		return svcStartDemand
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
