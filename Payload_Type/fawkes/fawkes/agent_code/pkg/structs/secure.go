package structs

import (
	"runtime/debug"
	"unsafe"
)

// safeZero overwrites a byte slice with zeros, recovering gracefully if the
// memory is read-only (e.g., string literals in .rodata). Uses SetPanicOnFault
// to convert SIGSEGV/SIGBUS from read-only writes into recoverable panics —
// by default Go only converts nil-range faults (<0x1000) to panics and treats
// other addresses as fatal via throw("fault").
func safeZero(b []byte) {
	prev := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(prev)
	defer func() { recover() }()
	clear(b)
}

// ZeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
// Use this to wipe cryptographic keys, decrypted secrets, and other sensitive byte data
// after use, reducing the window for memory forensics to recover them.
func ZeroBytes(b []byte) {
	safeZero(b)
}

// ZeroString zeros the backing memory of a Go string using unsafe.
// After calling, the original string variable is set to "".
//
// Safe to call on any string, including string literals in read-only memory.
// If the backing memory is read-only, the zero attempt is silently skipped
// and the variable is still set to "".
//
// Limitations: this only clears the specific backing array for this string variable.
// Copies made by concatenation, fmt.Sprintf, or slice operations are NOT affected.
// Despite this, zeroing the primary copy is valuable because it clears the most
// likely target for memory scanners and reduces the forensic surface area.
func ZeroString(s *string) {
	if len(*s) > 0 {
		b := unsafe.Slice(unsafe.StringData(*s), len(*s))
		safeZero(b)
	}
	*s = ""
}
