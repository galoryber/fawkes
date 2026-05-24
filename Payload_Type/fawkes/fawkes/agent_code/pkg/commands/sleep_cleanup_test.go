package commands

import (
	"testing"
)

func TestPreSleepCleanup_NoPanic(t *testing.T) {
	// Should not panic with no state
	PreSleepCleanup()
}

func TestPostSleepInit_NoPanic(t *testing.T) {
	// Should not panic
	PostSleepInit()
}

func TestZeroBytes_Empty(t *testing.T) {
	// Should not panic on empty/nil slice
	zeroBytes(nil)
	zeroBytes([]byte{})
}

func TestZeroBytes_Clears(t *testing.T) {
	data := []byte("sensitive credential data here")
	zeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte %d not zeroed: %d", i, b)
		}
	}
}

func TestSetLastOutput_And_Clear(t *testing.T) {
	data := []byte("hashdump output: Administrator:500:aad3b435...")
	SetLastOutput(data)

	if lastOutputBuffer == nil {
		t.Fatal("lastOutputBuffer should be set")
	}

	clearLastOutput()
	if lastOutputBuffer != nil {
		t.Error("lastOutputBuffer should be nil after clear")
	}
}

func TestClearLastOutput_Empty(t *testing.T) {
	lastOutputBuffer = nil
	clearLastOutput() // Should not panic
}

func TestPreSleepCleanup_ClearsOutput(t *testing.T) {
	data := []byte("credential dump content")
	SetLastOutput(data)

	PreSleepCleanup()

	if lastOutputBuffer != nil {
		t.Error("PreSleepCleanup should clear lastOutputBuffer")
	}
}
