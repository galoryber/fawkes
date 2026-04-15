package commands

import (
	"encoding/binary"
	"fmt"
)

type audioCaptureParams struct {
	Duration   int    `json:"duration"`
	SampleRate int    `json:"sample_rate"`
	Channels   int    `json:"channels"`
	Device     string `json:"device"`
}

type audioCaptureResult struct {
	Duration    string `json:"duration"`
	SampleRate  int    `json:"sample_rate"`
	Channels    int    `json:"channels"`
	BitsPerSamp int    `json:"bits_per_sample"`
	DataSize    int    `json:"data_size"`
	DeviceUsed  string `json:"device_used"`
}

// buildWAVHeader creates a standard 44-byte PCM WAV header.
// WAV format: RIFF header + fmt chunk + data chunk.
func buildWAVHeader(dataSize, sampleRate, channels, bitsPerSample int) []byte {
	byteRate := sampleRate * channels * (bitsPerSample / 8)
	blockAlign := channels * (bitsPerSample / 8)
	fileSize := 36 + dataSize // RIFF chunk size = file size - 8

	hdr := make([]byte, 44)
	copy(hdr[0:4], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(fileSize))
	copy(hdr[8:12], "WAVE")

	// fmt sub-chunk
	copy(hdr[12:16], "fmt ")
	binary.LittleEndian.PutUint32(hdr[16:20], 16) // PCM format chunk size
	binary.LittleEndian.PutUint16(hdr[20:22], 1)  // PCM format
	binary.LittleEndian.PutUint16(hdr[22:24], uint16(channels))
	binary.LittleEndian.PutUint32(hdr[24:28], uint32(sampleRate))
	binary.LittleEndian.PutUint32(hdr[28:32], uint32(byteRate))
	binary.LittleEndian.PutUint16(hdr[32:34], uint16(blockAlign))
	binary.LittleEndian.PutUint16(hdr[34:36], uint16(bitsPerSample))

	// data sub-chunk
	copy(hdr[36:40], "data")
	binary.LittleEndian.PutUint32(hdr[40:44], uint32(dataSize))

	return hdr
}

func audioDefaultParams(params *audioCaptureParams) {
	if params.Duration <= 0 {
		params.Duration = 10
	}
	if params.Duration > 300 {
		params.Duration = 300
	}
	if params.SampleRate <= 0 {
		params.SampleRate = 16000 // 16kHz — good quality for voice, small file size
	}
	if params.Channels <= 0 {
		params.Channels = 1 // Mono
	}
	if params.Channels > 2 {
		params.Channels = 2
	}
}

func audioEstimateSize(params *audioCaptureParams) string {
	bitsPerSample := 16
	bytes := params.Duration * params.SampleRate * params.Channels * (bitsPerSample / 8)
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}
