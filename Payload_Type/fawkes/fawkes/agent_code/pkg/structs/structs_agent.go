package structs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Agent represents the agent instance
type Agent struct {
	PayloadUUID       string `json:"payload_uuid"`
	Architecture      string `json:"architecture"`
	Domain            string `json:"domain"`
	ExternalIP        string `json:"external_ip"`
	Host              string `json:"host"`
	Integrity         int    `json:"integrity_level"`
	InternalIP        string `json:"internal_ip"`
	OS                string `json:"os"`
	PID               int    `json:"pid"`
	ProcessName       string `json:"process_name"`
	SleepInterval     int    `json:"sleep_interval"`
	Jitter            int    `json:"jitter"`
	JitterProfile     string `json:"-"` // uniform (default), normal, exponential
	User              string `json:"user"`
	Description       string `json:"description"`
	KillDate          int64  `json:"-"` // Unix timestamp. 0 = disabled. Agent exits when time exceeds this.
	WorkingHoursStart int    `json:"-"` // Minutes from midnight (e.g., 540 = 09:00). 0 with End=0 means disabled.
	WorkingHoursEnd   int    `json:"-"` // Minutes from midnight (e.g., 1020 = 17:00). 0 with Start=0 means disabled.
	WorkingDays       []int  `json:"-"` // ISO weekday numbers: Mon=1 .. Sun=7. Empty means all days.
	DefaultPPID       int    `json:"-"` // Default parent PID for subprocess spoofing. 0 = disabled.
}

// UpdateSleepParams updates the agent's sleep parameters
func (a *Agent) UpdateSleepParams(interval, jitter int) {
	a.SleepInterval = interval
	a.Jitter = jitter
}

// UpdateWorkingHours updates the agent's working hours configuration
func (a *Agent) UpdateWorkingHours(startMinutes, endMinutes int, days []int) {
	a.WorkingHoursStart = startMinutes
	a.WorkingHoursEnd = endMinutes
	a.WorkingDays = days
}

// WorkingHoursEnabled returns true if working hours restrictions are configured
func (a *Agent) WorkingHoursEnabled() bool {
	return a.WorkingHoursStart != 0 || a.WorkingHoursEnd != 0
}

// IsWithinWorkingHours checks if the current time falls within configured working hours.
// Returns true if working hours are disabled (always active) or if current time is within bounds.
func (a *Agent) IsWithinWorkingHours(now time.Time) bool {
	if !a.WorkingHoursEnabled() {
		return true
	}

	// Check day of week if working days are configured
	if len(a.WorkingDays) > 0 {
		isoDay := int(now.Weekday()) // Sunday=0 in Go
		if isoDay == 0 {
			isoDay = 7 // Convert to ISO: Sunday=7
		}
		dayAllowed := false
		for _, d := range a.WorkingDays {
			if d == isoDay {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			return false
		}
	}

	// Check time of day
	currentMinutes := now.Hour()*60 + now.Minute()
	if a.WorkingHoursStart <= a.WorkingHoursEnd {
		// Normal range: e.g., 09:00-17:00
		return currentMinutes >= a.WorkingHoursStart && currentMinutes < a.WorkingHoursEnd
	}
	// Overnight range: e.g., 22:00-06:00
	return currentMinutes >= a.WorkingHoursStart || currentMinutes < a.WorkingHoursEnd
}

// MinutesUntilWorkingHours calculates how many minutes until the next working period.
// Returns 0 if already within working hours. Uses local time.
func (a *Agent) MinutesUntilWorkingHours(now time.Time) int {
	if a.IsWithinWorkingHours(now) {
		return 0
	}

	currentMinutes := now.Hour()*60 + now.Minute()

	// If working days are set, check if today is a working day
	if len(a.WorkingDays) > 0 {
		isoDay := int(now.Weekday())
		if isoDay == 0 {
			isoDay = 7
		}

		// Check if today is a working day but we're outside hours
		todayIsWorkDay := false
		for _, d := range a.WorkingDays {
			if d == isoDay {
				todayIsWorkDay = true
				break
			}
		}

		if todayIsWorkDay && currentMinutes < a.WorkingHoursStart {
			// Today is a work day and start hasn't passed yet
			return a.WorkingHoursStart - currentMinutes
		}

		// Find the next working day
		for daysAhead := 1; daysAhead <= 7; daysAhead++ {
			nextDay := ((isoDay - 1 + daysAhead) % 7) + 1
			for _, d := range a.WorkingDays {
				if d == nextDay {
					// Calculate minutes until start of that day
					minutesToMidnight := 1440 - currentMinutes
					minutesAfterMidnight := (daysAhead-1)*1440 + a.WorkingHoursStart
					return minutesToMidnight + minutesAfterMidnight
				}
			}
		}
	}

	// No working days restriction, just time-of-day
	if currentMinutes >= a.WorkingHoursEnd && a.WorkingHoursStart <= a.WorkingHoursEnd {
		// Past end time, sleep until tomorrow's start
		return (1440 - currentMinutes) + a.WorkingHoursStart
	}
	if currentMinutes < a.WorkingHoursStart {
		return a.WorkingHoursStart - currentMinutes
	}

	// Fallback for overnight ranges
	return a.WorkingHoursStart - currentMinutes + 1440
}

// ParseWorkingHoursTime parses "HH:MM" format into minutes from midnight
func ParseWorkingHoursTime(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format %q, expected HH:MM", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour %q", parts[0])
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute %q", parts[1])
	}
	return h*60 + m, nil
}

// ParseWorkingDays parses "1,2,3,4,5" into a slice of ISO weekday numbers
func ParseWorkingDays(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	days := make([]int, 0, len(parts))
	for _, p := range parts {
		d, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || d < 1 || d > 7 {
			return nil, fmt.Errorf("invalid day %q, expected 1-7 (Mon=1, Sun=7)", p)
		}
		days = append(days, d)
	}
	return days, nil
}

// FormatWorkingHoursTime formats minutes from midnight as "HH:MM"
func FormatWorkingHoursTime(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/60, minutes%60)
}
