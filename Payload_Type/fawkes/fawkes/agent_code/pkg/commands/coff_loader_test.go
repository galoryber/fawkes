//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestLoadAndRunBOF_EmptyBytes(t *testing.T) {
	_, err := LoadAndRunBOF([]byte{}, nil, "go", 0)
	if err == nil {
		t.Error("LoadAndRunBOF with empty bytes should return error")
	}
}

func TestLoadAndRunBOF_InvalidCOFF(t *testing.T) {
	// Random bytes that aren't a valid COFF
	_, err := LoadAndRunBOF([]byte{0x01, 0x02, 0x03, 0x04}, nil, "go", 0)
	if err == nil {
		t.Error("LoadAndRunBOF with invalid COFF should return error")
	}
}

func TestCoffImageScnMemExecute_Value(t *testing.T) {
	if coffImageScnMemExecute != 0x20000000 {
		t.Errorf("coffImageScnMemExecute = 0x%X, want 0x20000000", coffImageScnMemExecute)
	}
}

func TestBeaconCallbackConstants(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"CALLBACK_OUTPUT", beaconCallbackOutput, 0x00},
		{"CALLBACK_ERROR", beaconCallbackError, 0x0d},
		{"CALLBACK_OUTPUT_OEM", beaconCallbackOutputOEM, 0x1e},
		{"CALLBACK_OUTPUT_UTF8", beaconCallbackOutputUTF8, 0x20},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.got, tt.want)
		}
	}
}

func TestBofOutputMsg_ErrorPrefix(t *testing.T) {
	ch := make(chan interface{}, 10)

	ch <- bofOutputMsg{outType: beaconCallbackOutput, text: "normal output"}
	ch <- bofOutputMsg{outType: beaconCallbackError, text: "error output"}
	ch <- bofOutputMsg{outType: beaconCallbackOutputUTF8, text: "utf8 output"}
	close(ch)

	var got []string
	for msg := range ch {
		switch m := msg.(type) {
		case bofOutputMsg:
			if m.outType == beaconCallbackError {
				got = append(got, "[ERROR] "+m.text)
			} else {
				got = append(got, m.text)
			}
		}
	}

	want := []string{"normal output", "[ERROR] error output", "utf8 output"}
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("message %d = %q, want %q", i, got[i], want[i])
		}
	}
}
