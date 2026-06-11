package commands

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestCheckTCPPort_Open(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	result := checkTCPPort(nil, "127.0.0.1", port, 2*time.Second)
	if result != "open" {
		t.Errorf("expected 'open', got %q", result)
	}
}

func TestCheckTCPPort_Closed(t *testing.T) {
	result := checkTCPPort(nil, "127.0.0.1", "1", 1*time.Second)
	if result == "open" {
		t.Error("expected closed/error, got 'open'")
	}
	if result != "timeout" {
		if len(result) < 7 || result[:7] != "closed:" {
			t.Errorf("expected 'closed: ...' prefix, got %q", result)
		}
	}
}

func TestCheckTCPPort_WithContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	result := checkTCPPort(ctx, "127.0.0.1", port, 2*time.Second)
	if result != "open" {
		t.Errorf("expected 'open', got %q", result)
	}
}

func TestCheckTCPPort_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := checkTCPPort(ctx, "127.0.0.1", "80", 5*time.Second)
	if result == "open" {
		t.Error("expected failure with cancelled context, got 'open'")
	}
}

func TestIsTimeout_Nil(t *testing.T) {
	if isTimeout(nil) {
		t.Error("expected false for nil error")
	}
}

func TestIsTimeout_NonNetError(t *testing.T) {
	if isTimeout(errors.New("not a net error")) {
		t.Error("expected false for non-net error")
	}
}

type mockTimeoutError struct {
	timeout bool
}

func (e *mockTimeoutError) Error() string   { return "mock error" }
func (e *mockTimeoutError) Timeout() bool   { return e.timeout }
func (e *mockTimeoutError) Temporary() bool { return false }

func TestIsTimeout_NetErrorTimeout(t *testing.T) {
	if !isTimeout(&mockTimeoutError{timeout: true}) {
		t.Error("expected true for timeout net.Error")
	}
}

func TestIsTimeout_NetErrorNonTimeout(t *testing.T) {
	if isTimeout(&mockTimeoutError{timeout: false}) {
		t.Error("expected false for non-timeout net.Error")
	}
}
