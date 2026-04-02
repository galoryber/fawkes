//go:build !windows

package commands

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"fawkes/pkg/structs"
)

func TestStatFileType_NamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipePath := filepath.Join(dir, "testpipe")
	if err := syscall.Mkfifo(pipePath, 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	info, err := os.Lstat(pipePath)
	if err != nil {
		t.Fatalf("cannot stat FIFO: %v", err)
	}

	ft := statFileType(info)
	if ft != "named pipe (FIFO)" {
		t.Errorf("expected 'named pipe (FIFO)', got %q", ft)
	}
}

func TestStatFileType_Socket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer listener.Close()

	info, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("cannot stat socket: %v", err)
	}

	ft := statFileType(info)
	if ft != "socket" {
		t.Errorf("expected 'socket', got %q", ft)
	}
}

func TestStatExecute_NamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipePath := filepath.Join(dir, "testpipe")
	if err := syscall.Mkfifo(pipePath, 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: pipePath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "named pipe") {
		t.Error("should identify as named pipe")
	}
}
