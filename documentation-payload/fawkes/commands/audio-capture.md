+++
title = "audio-capture"
chapter = false
weight = 8
hidden = false
+++

## Summary

Record audio from the system microphone and upload the recording as a WAV file to Mythic. Supports configurable duration, sample rate, and channel count. Cross-platform: Windows (waveIn API), Linux (arecord/parecord), macOS (rec/ffmpeg).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| duration | No | 10 | Recording duration in seconds (max: 300) |
| sample_rate | No | 16000 | Sample rate in Hz. 8000=phone, 16000=voice, 44100=CD quality |
| channels | No | 1 | Number of channels (1=mono, 2=stereo) |
| device | No | default | Audio input device. Linux: ALSA device name (e.g. hw:0,0). Windows/macOS: default |

## Usage

### Quick 10-second recording (defaults)
```
audio-capture
```

### Record 30 seconds at CD quality
```
audio-capture -duration 30 -sample_rate 44100 -channels 2
```

### Record 60 seconds from a specific Linux device
```
audio-capture -duration 60 -device hw:1,0
```

### Minimal quality (small file, phone quality)
```
audio-capture -duration 120 -sample_rate 8000
```

## Platform Details

| Platform | Mechanism | Requirements |
|----------|-----------|-------------|
| Windows | waveIn API (winmm.dll) | Administrator not required, but may need microphone privacy permission |
| Linux | arecord (ALSA) with parecord fallback | alsa-utils or pulseaudio-utils package |
| macOS | rec (SoX) with ffmpeg fallback | SoX or ffmpeg (brew install sox/ffmpeg). TCC microphone permission required |

## Output

The recording is uploaded as a WAV file to Mythic's file browser. JSON metadata is returned:

```json
{
  "duration": "10s",
  "sample_rate": 16000,
  "channels": 1,
  "bits_per_sample": 16,
  "data_size": 320044,
  "device_used": "default (WAVE_MAPPER)"
}
```

## File Size Estimates

| Duration | 8kHz Mono | 16kHz Mono | 44.1kHz Stereo |
|----------|-----------|------------|----------------|
| 10s | 160 KB | 312 KB | 1.7 MB |
| 30s | 480 KB | 937 KB | 5.1 MB |
| 60s | 960 KB | 1.8 MB | 10.1 MB |
| 300s | 4.7 MB | 9.2 MB | 50.4 MB |

## OPSEC Considerations

- **Windows**: Uses waveIn API from winmm.dll. May trigger Windows audio privacy indicators (microphone icon in taskbar)
- **Linux**: Spawns `arecord` or `parecord` process — visible in `ps` output
- **macOS**: May trigger TCC microphone permission dialog if not pre-authorized. Spawns `rec` or `ffmpeg` process
- WAV file is uploaded to Mythic — consider bandwidth constraints for long recordings
- All audio data is PCM (uncompressed) — no codec dependencies required

## MITRE ATT&CK Mapping

- **T1123** — Audio Capture
