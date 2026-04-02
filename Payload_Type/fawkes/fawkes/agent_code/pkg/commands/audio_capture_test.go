package commands

import (
	"encoding/binary"
	"testing"
)

func TestBuildWAVHeader(t *testing.T) {
	tests := []struct {
		name          string
		dataSize      int
		sampleRate    int
		channels      int
		bitsPerSample int
	}{
		{"16kHz mono 16-bit", 32000, 16000, 1, 16},
		{"44.1kHz stereo 16-bit", 176400, 44100, 2, 16},
		{"8kHz mono 16-bit", 16000, 8000, 1, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := buildWAVHeader(tt.dataSize, tt.sampleRate, tt.channels, tt.bitsPerSample)

			if len(hdr) != 44 {
				t.Fatalf("header length = %d, want 44", len(hdr))
			}

			// Verify RIFF header
			if string(hdr[0:4]) != "RIFF" {
				t.Errorf("missing RIFF marker")
			}
			riffSize := binary.LittleEndian.Uint32(hdr[4:8])
			if riffSize != uint32(36+tt.dataSize) {
				t.Errorf("RIFF size = %d, want %d", riffSize, 36+tt.dataSize)
			}
			if string(hdr[8:12]) != "WAVE" {
				t.Errorf("missing WAVE marker")
			}

			// Verify fmt chunk
			if string(hdr[12:16]) != "fmt " {
				t.Errorf("missing fmt marker")
			}
			fmtSize := binary.LittleEndian.Uint32(hdr[16:20])
			if fmtSize != 16 {
				t.Errorf("fmt size = %d, want 16", fmtSize)
			}
			audioFmt := binary.LittleEndian.Uint16(hdr[20:22])
			if audioFmt != 1 {
				t.Errorf("audio format = %d, want 1 (PCM)", audioFmt)
			}
			ch := binary.LittleEndian.Uint16(hdr[22:24])
			if ch != uint16(tt.channels) {
				t.Errorf("channels = %d, want %d", ch, tt.channels)
			}
			sr := binary.LittleEndian.Uint32(hdr[24:28])
			if sr != uint32(tt.sampleRate) {
				t.Errorf("sample rate = %d, want %d", sr, tt.sampleRate)
			}
			byteRate := binary.LittleEndian.Uint32(hdr[28:32])
			expectedByteRate := uint32(tt.sampleRate * tt.channels * (tt.bitsPerSample / 8))
			if byteRate != expectedByteRate {
				t.Errorf("byte rate = %d, want %d", byteRate, expectedByteRate)
			}
			blockAlign := binary.LittleEndian.Uint16(hdr[32:34])
			expectedBlockAlign := uint16(tt.channels * (tt.bitsPerSample / 8))
			if blockAlign != expectedBlockAlign {
				t.Errorf("block align = %d, want %d", blockAlign, expectedBlockAlign)
			}
			bps := binary.LittleEndian.Uint16(hdr[34:36])
			if bps != uint16(tt.bitsPerSample) {
				t.Errorf("bits per sample = %d, want %d", bps, tt.bitsPerSample)
			}

			// Verify data chunk
			if string(hdr[36:40]) != "data" {
				t.Errorf("missing data marker")
			}
			dataSize := binary.LittleEndian.Uint32(hdr[40:44])
			if dataSize != uint32(tt.dataSize) {
				t.Errorf("data size = %d, want %d", dataSize, tt.dataSize)
			}
		})
	}
}

func TestAudioDefaultParams(t *testing.T) {
	t.Run("zero values get defaults", func(t *testing.T) {
		p := &audioCaptureParams{}
		audioDefaultParams(p)
		if p.Duration != 10 {
			t.Errorf("duration = %d, want 10", p.Duration)
		}
		if p.SampleRate != 16000 {
			t.Errorf("sample_rate = %d, want 16000", p.SampleRate)
		}
		if p.Channels != 1 {
			t.Errorf("channels = %d, want 1", p.Channels)
		}
	})

	t.Run("over max duration capped", func(t *testing.T) {
		p := &audioCaptureParams{Duration: 999}
		audioDefaultParams(p)
		if p.Duration != 300 {
			t.Errorf("duration = %d, want 300", p.Duration)
		}
	})

	t.Run("over max channels capped", func(t *testing.T) {
		p := &audioCaptureParams{Channels: 5}
		audioDefaultParams(p)
		if p.Channels != 2 {
			t.Errorf("channels = %d, want 2", p.Channels)
		}
	})

	t.Run("valid values preserved", func(t *testing.T) {
		p := &audioCaptureParams{Duration: 30, SampleRate: 44100, Channels: 2}
		audioDefaultParams(p)
		if p.Duration != 30 || p.SampleRate != 44100 || p.Channels != 2 {
			t.Errorf("params modified: %+v", p)
		}
	})
}

func TestAudioEstimateSize(t *testing.T) {
	tests := []struct {
		params audioCaptureParams
		want   string
	}{
		{audioCaptureParams{Duration: 10, SampleRate: 16000, Channels: 1}, "312.5 KB"},
		{audioCaptureParams{Duration: 60, SampleRate: 44100, Channels: 2}, "10.1 MB"},
	}
	for _, tt := range tests {
		got := audioEstimateSize(&tt.params)
		if got != tt.want {
			t.Errorf("estimate(%+v) = %q, want %q", tt.params, got, tt.want)
		}
	}
}
