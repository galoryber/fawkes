//go:build darwin && arm64

package commands

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// Mach IPC message types and MIG subsystem IDs for thread manipulation.
// These implement the wire format for kernel MIG calls via mach_msg_trap.

// mach_msg option flags
const (
	machSendMsg    = 0x00000001 // MACH_SEND_MSG
	machRcvMsg     = 0x00000002 // MACH_RCV_MSG
	machSendRcvMsg = machSendMsg | machRcvMsg
)

// mach_msg_type_name_t
const (
	machMsgTypeCopySend     = 19 // MACH_MSG_TYPE_COPY_SEND
	machMsgTypeMakeSendOnce = 20 // MACH_MSG_TYPE_MAKE_SEND_ONCE
)

// MIG subsystem message IDs
const (
	migTaskThreadsReqID  = 3413
	migTaskThreadsRepID  = 3513
	migThreadGetStateReq = 3603
	migThreadGetStateRep = 3703
	migThreadSetStateReq = 3604
	migThreadSetStateRep = 3704
	migThreadResumeReq   = 3605
	migThreadResumeRep   = 3705
	migThreadSuspendReq  = 3606
	migThreadSuspendRep  = 3706
)

// ARM64 thread state
const (
	armThreadState64      = 6  // ARM_THREAD_STATE64
	armThreadState64Count = 68 // ARM_THREAD_STATE64_COUNT (272 bytes / 4)
)

// ARM64ThreadState holds the ARM64 register state.
// Layout matches XNU's arm_thread_state64_t.
type ARM64ThreadState struct {
	X  [29]uint64 // general purpose registers x0-x28
	FP uint64     // x29 frame pointer
	LR uint64     // x30 link register
	SP uint64     // stack pointer
	PC uint64     // program counter
	CPSR uint32   // current program status register
	Pad  uint32   // alignment padding
}

// ndrRecord is the standard NDR encoding descriptor for MIG messages.
var ndrRecord = [8]byte{0, 0, 0, 0, 1, 0, 0, 0} // little-endian, no float/char encoding

func machMsgBits(remote, local uint32) uint32 {
	return remote | (local << 8)
}

// machMsgBitsComplex sets the complex bit in message flags.
func machMsgBitsComplex(remote, local uint32) uint32 {
	return machMsgBits(remote, local) | (1 << 31) // MACH_MSGH_BITS_COMPLEX
}

// machMsgSendRecv sends a MIG request and receives the reply.
func machMsgSendRecv(msg []byte, sendSize, rcvSize uint32, replyPort uint32) error {
	r1, _, _ := syscall.Syscall6(
		libc_mach_msg_trampoline_addr,
		uintptr(unsafe.Pointer(&msg[0])),
		uintptr(machSendRcvMsg),
		uintptr(sendSize),
		uintptr(rcvSize),
		uintptr(replyPort),
		0, // timeout = MACH_MSG_TIMEOUT_NONE
	)
	if r1 != 0 {
		return fmt.Errorf("mach_msg failed (return=%d)", int32(r1))
	}
	return nil
}

// machThreadGetState retrieves the ARM64 thread state via MIG.
func machThreadGetState(thread uint32) (*ARM64ThreadState, error) {
	replyPort := machReplyPort()
	if replyPort == 0 {
		return nil, fmt.Errorf("mach_reply_port returned 0")
	}

	// Build request: header(24) + NDR(8) + flavor(4) + count(4) = 40 bytes
	const reqSize = 40
	// Reply: header(24) + NDR(8) + RetCode(4) + count(4) + state(272) = 312 bytes
	const repSize = 312

	buf := make([]byte, repSize) // reuse for both request and reply

	// Fill request header
	binary.LittleEndian.PutUint32(buf[0:], machMsgBits(machMsgTypeCopySend, machMsgTypeMakeSendOnce))
	binary.LittleEndian.PutUint32(buf[4:], reqSize)
	binary.LittleEndian.PutUint32(buf[8:], thread)     // remote port
	binary.LittleEndian.PutUint32(buf[12:], replyPort)  // local port
	binary.LittleEndian.PutUint32(buf[16:], 0)          // voucher
	binary.LittleEndian.PutUint32(buf[20:], migThreadGetStateReq) // msg ID

	// NDR record
	copy(buf[24:], ndrRecord[:])

	// flavor and count
	binary.LittleEndian.PutUint32(buf[32:], armThreadState64)
	binary.LittleEndian.PutUint32(buf[36:], armThreadState64Count)

	if err := machMsgSendRecv(buf, reqSize, repSize, replyPort); err != nil {
		return nil, fmt.Errorf("thread_get_state: %w", err)
	}

	// Parse reply: header(24) + NDR(8) + RetCode(4) + count(4) + state
	retCode := int32(binary.LittleEndian.Uint32(buf[36:]))
	if retCode != 0 {
		return nil, fmt.Errorf("thread_get_state kern_return=%d", retCode)
	}

	stateCnt := binary.LittleEndian.Uint32(buf[36:])
	_ = stateCnt // count should be armThreadState64Count

	var state ARM64ThreadState
	stateBytes := buf[40 : 40+272]
	for i := 0; i < 29; i++ {
		state.X[i] = binary.LittleEndian.Uint64(stateBytes[i*8:])
	}
	state.FP = binary.LittleEndian.Uint64(stateBytes[232:])
	state.LR = binary.LittleEndian.Uint64(stateBytes[240:])
	state.SP = binary.LittleEndian.Uint64(stateBytes[248:])
	state.PC = binary.LittleEndian.Uint64(stateBytes[256:])
	state.CPSR = binary.LittleEndian.Uint32(stateBytes[264:])

	return &state, nil
}

// machThreadSetState sets the ARM64 thread state via MIG.
func machThreadSetState(thread uint32, state *ARM64ThreadState) error {
	replyPort := machReplyPort()
	if replyPort == 0 {
		return fmt.Errorf("mach_reply_port returned 0")
	}

	// Request: header(24) + NDR(8) + flavor(4) + count(4) + state(272) = 312 bytes
	const reqSize = 312
	// Reply: header(24) + NDR(8) + RetCode(4) = 36 bytes
	const repSize = 36

	buf := make([]byte, reqSize)

	binary.LittleEndian.PutUint32(buf[0:], machMsgBits(machMsgTypeCopySend, machMsgTypeMakeSendOnce))
	binary.LittleEndian.PutUint32(buf[4:], reqSize)
	binary.LittleEndian.PutUint32(buf[8:], thread)
	binary.LittleEndian.PutUint32(buf[12:], replyPort)
	binary.LittleEndian.PutUint32(buf[16:], 0)
	binary.LittleEndian.PutUint32(buf[20:], migThreadSetStateReq)

	copy(buf[24:], ndrRecord[:])
	binary.LittleEndian.PutUint32(buf[32:], armThreadState64)
	binary.LittleEndian.PutUint32(buf[36:], armThreadState64Count)

	// Serialize state at offset 40
	stateOff := 40
	for i := 0; i < 29; i++ {
		binary.LittleEndian.PutUint64(buf[stateOff+i*8:], state.X[i])
	}
	binary.LittleEndian.PutUint64(buf[stateOff+232:], state.FP)
	binary.LittleEndian.PutUint64(buf[stateOff+240:], state.LR)
	binary.LittleEndian.PutUint64(buf[stateOff+248:], state.SP)
	binary.LittleEndian.PutUint64(buf[stateOff+256:], state.PC)
	binary.LittleEndian.PutUint32(buf[stateOff+264:], state.CPSR)

	repBuf := make([]byte, repSize)
	copy(repBuf[:reqSize], buf[:])

	// Can't reuse buf since reqSize > repSize for set. Need separate buffers.
	// Actually mach_msg reuses the buffer: it sends reqSize bytes then receives into same buffer.
	if err := machMsgSendRecv(buf[:reqSize], reqSize, repSize, replyPort); err != nil {
		return fmt.Errorf("thread_set_state: %w", err)
	}

	retCode := int32(binary.LittleEndian.Uint32(buf[36:]))
	if retCode != 0 {
		return fmt.Errorf("thread_set_state kern_return=%d", retCode)
	}

	return nil
}

// machThreadResume resumes a suspended Mach thread via MIG.
func machThreadResume(thread uint32) error {
	replyPort := machReplyPort()
	if replyPort == 0 {
		return fmt.Errorf("mach_reply_port returned 0")
	}

	// Request: header only = 24 bytes
	const reqSize = 24
	// Reply: header(24) + NDR(8) + RetCode(4) = 36 bytes
	const repSize = 36

	buf := make([]byte, repSize)

	binary.LittleEndian.PutUint32(buf[0:], machMsgBits(machMsgTypeCopySend, machMsgTypeMakeSendOnce))
	binary.LittleEndian.PutUint32(buf[4:], reqSize)
	binary.LittleEndian.PutUint32(buf[8:], thread)
	binary.LittleEndian.PutUint32(buf[12:], replyPort)
	binary.LittleEndian.PutUint32(buf[16:], 0)
	binary.LittleEndian.PutUint32(buf[20:], migThreadResumeReq)

	if err := machMsgSendRecv(buf, reqSize, repSize, replyPort); err != nil {
		return fmt.Errorf("thread_resume: %w", err)
	}

	retCode := int32(binary.LittleEndian.Uint32(buf[36:]))
	if retCode != 0 {
		return fmt.Errorf("thread_resume kern_return=%d", retCode)
	}

	return nil
}

// machThreadSuspend suspends a Mach thread via MIG.
func machThreadSuspend(thread uint32) error {
	replyPort := machReplyPort()
	if replyPort == 0 {
		return fmt.Errorf("mach_reply_port returned 0")
	}

	const reqSize = 24
	const repSize = 36

	buf := make([]byte, repSize)

	binary.LittleEndian.PutUint32(buf[0:], machMsgBits(machMsgTypeCopySend, machMsgTypeMakeSendOnce))
	binary.LittleEndian.PutUint32(buf[4:], reqSize)
	binary.LittleEndian.PutUint32(buf[8:], thread)
	binary.LittleEndian.PutUint32(buf[12:], replyPort)
	binary.LittleEndian.PutUint32(buf[16:], 0)
	binary.LittleEndian.PutUint32(buf[20:], migThreadSuspendReq)

	if err := machMsgSendRecv(buf, reqSize, repSize, replyPort); err != nil {
		return fmt.Errorf("thread_suspend: %w", err)
	}

	retCode := int32(binary.LittleEndian.Uint32(buf[36:]))
	if retCode != 0 {
		return fmt.Errorf("thread_suspend kern_return=%d", retCode)
	}

	return nil
}
