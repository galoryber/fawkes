package structs

import (
	"testing"
	"unsafe"
)

// heapStr creates a heap-allocated string (not a .rodata literal).
// This mirrors production behavior where strings come from JSON unmarshaling.
func heapStr(s string) string {
	return string([]byte(s))
}

func TestResponseWipe_ZerosUserOutput(t *testing.T) {
	output := heapStr("NT:aad3b435b51404eeaad3b435b51404ee")
	ptr := unsafe.StringData(output)

	r := Response{
		TaskID:     "task-1",
		UserOutput: output,
		Status:     "success",
		Completed:  true,
	}
	r.Wipe()

	if r.UserOutput != "" {
		t.Errorf("Wipe did not clear UserOutput: got %q", r.UserOutput)
	}
	backed := unsafe.Slice(ptr, 35)
	for i, b := range backed {
		if b != 0 {
			t.Errorf("Wipe did not zero UserOutput backing byte %d: got 0x%02x", i, b)
			break
		}
	}
}

func TestResponseWipe_ZerosCredentials(t *testing.T) {
	credVal := heapStr("aad3b435b51404eeaad3b435b51404ee:deadbeef")
	account := heapStr("Administrator")
	realm := heapStr("CONTOSO.LOCAL")
	credPtr := unsafe.StringData(credVal)
	creds := []MythicCredential{{
		CredentialType: heapStr("hash"),
		Realm:          realm,
		Account:        account,
		Credential:     credVal,
		Comment:        heapStr("hashdump"),
	}}

	r := Response{
		TaskID:      "task-2",
		UserOutput:  heapStr("test"),
		Credentials: &creds,
	}
	r.Wipe()

	if r.Credentials != nil {
		t.Error("Wipe did not nil Credentials pointer")
	}

	backed := unsafe.Slice(credPtr, 41)
	for i, b := range backed {
		if b != 0 {
			t.Errorf("Wipe did not zero credential backing byte %d: got 0x%02x", i, b)
			break
		}
	}
}

func TestResponseWipe_ZerosProcessResponse(t *testing.T) {
	r := Response{
		TaskID:          "task-3",
		ProcessResponse: heapStr("sensitive data"),
	}
	r.Wipe()

	if r.ProcessResponse != nil {
		t.Error("Wipe did not nil ProcessResponse")
	}
}

func TestResponseWipe_NilsProcesses(t *testing.T) {
	procs := []ProcessEntry{{ProcessID: 1234, Name: "svchost.exe"}}
	r := Response{
		TaskID:    "task-4",
		Processes: &procs,
	}
	r.Wipe()

	if r.Processes != nil {
		t.Error("Wipe did not nil Processes pointer")
	}
}

func TestResponseWipe_EmptyResponse(t *testing.T) {
	r := Response{}
	r.Wipe()
}

func TestResponseWipe_NilCredentials(t *testing.T) {
	r := Response{
		TaskID:     "task-5",
		UserOutput: heapStr("test"),
	}
	r.Wipe()
}

func TestResponseWipe_MultipleCredentials(t *testing.T) {
	creds := []MythicCredential{
		{Credential: heapStr("hash1"), Account: heapStr("user1"), Realm: heapStr("DOMAIN1")},
		{Credential: heapStr("hash2"), Account: heapStr("user2"), Realm: heapStr("DOMAIN2")},
		{Credential: heapStr("hash3"), Account: heapStr("user3"), Realm: heapStr("DOMAIN3")},
	}
	ptrs := make([]unsafe.Pointer, len(creds))
	for i := range creds {
		ptrs[i] = unsafe.Pointer(unsafe.StringData(creds[i].Credential))
	}

	r := Response{Credentials: &creds}
	r.Wipe()

	for i, ptr := range ptrs {
		backed := unsafe.Slice((*byte)(ptr), 5)
		for j, b := range backed {
			if b != 0 {
				t.Errorf("credential %d backing byte %d not zeroed: got 0x%02x", i, j, b)
				break
			}
		}
	}
}

func TestCommandResultWipe_ZerosOutput(t *testing.T) {
	output := heapStr("Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")
	ptr := unsafe.StringData(output)

	cr := CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
	cr.Wipe()

	if cr.Output != "" {
		t.Errorf("Wipe did not clear Output: got %q", cr.Output)
	}
	backed := unsafe.Slice(ptr, 10)
	for i, b := range backed {
		if b != 0 {
			t.Errorf("Wipe did not zero Output backing byte %d: got 0x%02x", i, b)
			break
		}
	}
}

func TestCommandResultWipe_ZerosCredentials(t *testing.T) {
	credVal := heapStr("secretpass")
	creds := []MythicCredential{
		{Credential: credVal, Account: heapStr("admin")},
	}
	credPtr := unsafe.StringData(credVal)

	cr := CommandResult{
		Output:      heapStr("test"),
		Credentials: &creds,
	}
	cr.Wipe()

	if cr.Credentials != nil {
		t.Error("Wipe did not nil Credentials pointer")
	}
	backed := unsafe.Slice(credPtr, 10)
	for i, b := range backed {
		if b != 0 {
			t.Errorf("Wipe did not zero credential backing byte %d: got 0x%02x", i, b)
			break
		}
	}
}

func TestCommandResultWipe_EmptyResult(t *testing.T) {
	cr := CommandResult{}
	cr.Wipe()
}

func TestResponseWipe_NonStringProcessResponse(t *testing.T) {
	r := Response{
		TaskID:          "task-6",
		ProcessResponse: map[string]interface{}{"key": "value"},
	}
	r.Wipe()
	if r.ProcessResponse != nil {
		t.Error("Wipe did not nil non-string ProcessResponse")
	}
}
