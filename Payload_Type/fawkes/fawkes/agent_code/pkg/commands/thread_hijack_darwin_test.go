//go:build darwin

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"unsafe"

	"fawkes/pkg/structs"
)

func TestThreadHijackDarwin_Name(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Name() != "thread-hijack" {
		t.Errorf("expected 'thread-hijack', got %q", cmd.Name())
	}
}

func TestThreadHijackDarwin_Description(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestThreadHijackDarwin_EmptyShellcode(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{"shellcode_b64":"","pid":1234}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty shellcode, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidPID(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	sc := base64.StdEncoding.EncodeToString([]byte{0xCC})
	task := structs.Task{Params: `{"shellcode_b64":"` + sc + `","pid":0}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for PID 0, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_NegativePID(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	sc := base64.StdEncoding.EncodeToString([]byte{0xCC})
	task := structs.Task{Params: `{"shellcode_b64":"` + sc + `","pid":-5}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for negative PID, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidBase64(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{"shellcode_b64":"not-valid-base64!!!","pid":1234}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid base64, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_InvalidJSON(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: `{bad json`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestThreadHijackDarwin_EmptyParams(t *testing.T) {
	cmd := &ThreadHijackCommand{}
	task := structs.Task{Params: ``}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestThreadHijackParams_Roundtrip(t *testing.T) {
	sc := base64.StdEncoding.EncodeToString([]byte{0x90, 0xCC})
	params := ThreadHijackParams{
		ShellcodeB64: sc,
		PID:          4567,
		TID:          8910,
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed ThreadHijackParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.PID != 4567 {
		t.Errorf("PID: expected 4567, got %d", parsed.PID)
	}
	if parsed.TID != 8910 {
		t.Errorf("TID: expected 8910, got %d", parsed.TID)
	}
}

func TestThreadHijackParams_TIDZeroAutoSelect(t *testing.T) {
	params := ThreadHijackParams{
		ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{0x90}),
		PID:          1234,
		TID:          0,
	}
	data, _ := json.Marshal(params)
	var parsed ThreadHijackParams
	json.Unmarshal(data, &parsed)
	if parsed.TID != 0 {
		t.Errorf("TID should be 0 for auto-select, got %d", parsed.TID)
	}
}

func TestARM64ThreadState_Size(t *testing.T) {
	var state ARM64ThreadState
	size := unsafe.Sizeof(state)
	// ARM64 thread state should be 272 bytes (68 * 4 = 272)
	// x0-x28(29*8=232) + FP(8) + LR(8) + SP(8) + PC(8) + CPSR(4) + Pad(4) = 272
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
		name     string
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
		name     string
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
