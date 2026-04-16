package commands

// PEB offsets for x86_64 Windows (from winternl.h and WinDbg !peb).
// These are cross-platform constants used by both the Windows implementation
// and platform-independent tests.

const (
	// PEB offsets (x64)
	pebProcessParametersOffset uintptr = 0x20 // PRTL_USER_PROCESS_PARAMETERS

	// RTL_USER_PROCESS_PARAMETERS offsets (x64)
	uppImagePathNameOffset uintptr = 0x60 // UNICODE_STRING ImagePathName
	uppCommandLineOffset   uintptr = 0x70 // UNICODE_STRING CommandLine
	uppWindowTitleOffset   uintptr = 0x80 // UNICODE_STRING WindowTitle

	// UNICODE_STRING struct size (x64): Length (2) + MaximumLength (2) + padding (4) + Buffer ptr (8)
	unicodeStringSize uintptr = 16
)
