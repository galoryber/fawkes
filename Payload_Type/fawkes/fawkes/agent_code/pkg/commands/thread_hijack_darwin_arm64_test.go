//go:build darwin && arm64

package commands

import (
	"testing"
	"unsafe"
)

func TestARM64ThreadState_Size(t *testing.T) {
	var state ARM64ThreadState
	size := unsafe.Sizeof(state)
	if size != 272 {
		t.Errorf("ARM64ThreadState size: expected 272, got %d", size)
	}
}

func TestARM64ThreadState_RegisterLayout(t *testing.T) {
	state := ARM64ThreadState{}
	state.X[0] = 0x1111111111111111
	state.X[28] = 0x2222222222222222
	state.FP = 0x3333333333333333
	state.LR = 0x4444444444444444
	state.SP = 0x5555555555555555
	state.PC = 0x6666666666666666
	state.CPSR = 0x77777777

	if state.X[0] != 0x1111111111111111 {
		t.Errorf("X[0] mismatch")
	}
	if state.X[28] != 0x2222222222222222 {
		t.Errorf("X[28] mismatch")
	}
	if state.FP != 0x3333333333333333 {
		t.Errorf("FP mismatch")
	}
	if state.LR != 0x4444444444444444 {
		t.Errorf("LR mismatch")
	}
	if state.SP != 0x5555555555555555 {
		t.Errorf("SP mismatch")
	}
	if state.PC != 0x6666666666666666 {
		t.Errorf("PC mismatch")
	}
	if state.CPSR != 0x77777777 {
		t.Errorf("CPSR mismatch")
	}
}

func TestDarwinPageSize(t *testing.T) {
	if darwinPageSize != 16384 {
		t.Errorf("expected 16384 (16KB), got %d", darwinPageSize)
	}
}

func TestThreadHijack_MachConstants(t *testing.T) {
	tests := []struct {
		name      string
		got, want int
	}{
		{"VM_FLAGS_ANYWHERE", vmFlagsAnywhere, 1},
		{"VM_PROT_READ", vmProtRead, 1},
		{"VM_PROT_WRITE", vmProtWrite, 2},
		{"VM_PROT_EXECUTE", vmProtExecute, 4},
		{"KERN_SUCCESS", kernSuccess, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.want, tt.got)
			}
		})
	}
}

func TestMIGMessageIDs(t *testing.T) {
	tests := []struct {
		name      string
		got, want uint32
	}{
		{"task_threads_req", migTaskThreadsReqID, 3413},
		{"task_threads_rep", migTaskThreadsRepID, 3513},
		{"thread_get_state_req", migThreadGetStateReq, 3603},
		{"thread_get_state_rep", migThreadGetStateRep, 3703},
		{"thread_set_state_req", migThreadSetStateReq, 3604},
		{"thread_set_state_rep", migThreadSetStateRep, 3704},
		{"thread_resume_req", migThreadResumeReq, 3605},
		{"thread_resume_rep", migThreadResumeRep, 3705},
		{"thread_suspend_req", migThreadSuspendReq, 3606},
		{"thread_suspend_rep", migThreadSuspendRep, 3706},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.want, tt.got)
			}
		})
	}
}

func TestMachMsgBits(t *testing.T) {
	bits := machMsgBits(machMsgTypeCopySend, machMsgTypeMakeSendOnce)
	if bits&0xFF != machMsgTypeCopySend {
		t.Errorf("remote bits wrong: 0x%X", bits)
	}
	if (bits>>8)&0xFF != machMsgTypeMakeSendOnce {
		t.Errorf("local bits wrong: 0x%X", bits)
	}
}

func TestMachMsgBitsComplex(t *testing.T) {
	bits := machMsgBitsComplex(machMsgTypeCopySend, machMsgTypeMakeSendOnce)
	if bits&(1<<31) == 0 {
		t.Error("COMPLEX bit should be set")
	}
}

func TestNDRRecord(t *testing.T) {
	expected := [8]byte{0, 0, 0, 0, 1, 0, 0, 0}
	if ndrRecord != expected {
		t.Errorf("NDR record mismatch: %v", ndrRecord)
	}
}
