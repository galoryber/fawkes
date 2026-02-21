+++
title = "sleep"
chapter = false
weight = 103
hidden = false
+++

## Summary

Update the agent's callback interval, jitter percentage, and working hours schedule. Working hours restrict the agent to only checking in during specified time windows and days, producing zero network traffic outside those periods.

### Arguments

#### interval
Sleep time in seconds.

#### jitter (optional)
Jitter percentage (0-100). Controls the randomness of the callback interval.

#### working_start (optional)
Working hours start time in HH:MM 24-hour format (e.g., `09:00`). Leave empty for no change. Set both start and end to `00:00` to disable working hours.

#### working_end (optional)
Working hours end time in HH:MM 24-hour format (e.g., `17:00`). Supports overnight ranges (e.g., start=22:00, end=06:00).

#### working_days (optional)
Comma-separated ISO weekday numbers (Mon=1 through Sun=7). E.g., `1,2,3,4,5` for weekdays only. Leave empty for no change. Set to `0` to disable day restrictions (all days active).

## Usage
```
sleep [seconds] [jitter%] [working_start] [working_end] [working_days]
```

Examples:
```
sleep 30
sleep 60 20
sleep 10 10 09:00 17:00 1,2,3,4,5
sleep 10 10 00:00 00:00
```

JSON format:
```json
{"interval": 10, "jitter": 10, "working_start": "09:00", "working_end": "17:00", "working_days": "1,2,3,4,5"}
```

Working hours can also be set at build time via payload build parameters (`working_hours_start`, `working_hours_end`, `working_days`).

## MITRE ATT&CK Mapping

- **T1029** - Scheduled Transfer
