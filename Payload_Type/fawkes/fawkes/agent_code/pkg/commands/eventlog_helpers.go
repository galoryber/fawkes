package commands

import "fmt"

// windowsFileTimeToString converts a Windows FILETIME (100-ns intervals since
// 1601-01-01) to a UTC date/time string without depending on the time package.
func windowsFileTimeToString(ft uint64) string {
	if ft == 0 {
		return "unknown"
	}
	// FILETIME is 100-nanosecond intervals since 1601-01-01
	// Epoch difference: 1601 to 1970 = 11644473600 seconds = 116444736000000000 100-ns intervals
	const epochDiff100ns = 116444736000000000
	if ft < epochDiff100ns {
		return "unknown"
	}
	unixSec := int64((ft - epochDiff100ns) / 10000000)
	days := unixSec / 86400
	rem := unixSec % 86400
	hours := rem / 3600
	mins := (rem % 3600) / 60
	secs := rem % 60
	year, month, day := daysToDate(days)
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d UTC", year, month, day, hours, mins, secs)
}

// daysToDate converts a Unix day count (days since 1970-01-01) to a calendar
// date using the Howard Hinnant algorithm.
// See: https://howardhinnant.github.io/date_algorithms.html
func daysToDate(days int64) (int64, int64, int64) {
	z := days + 719468
	era := z / 146097
	if z < 0 {
		era = (z - 146096) / 146097
	}
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp + 3
	if mp >= 10 {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

// nlgSidUsageString converts a SID_NAME_USE value to a human-readable string.
func nlgSidUsageString(usage uint32) string {
	switch usage {
	case 1:
		return "User"
	case 2:
		return "Group"
	case 3:
		return "Domain"
	case 4:
		return "Alias"
	case 5:
		return "WellKnownGroup"
	case 6:
		return "DeletedAccount"
	case 9:
		return "Computer"
	default:
		return fmt.Sprintf("Type(%d)", usage)
	}
}
