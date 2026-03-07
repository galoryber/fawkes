package structs

import "unsafe"

// ZeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
// Use this to wipe cryptographic keys, decrypted secrets, and other sensitive byte data
// after use, reducing the window for memory forensics to recover them.
func ZeroBytes(b []byte) {
	clear(b)
}

// ZeroString zeros the backing memory of a Go string using unsafe.
// After calling, the original string variable is set to "".
//
// Limitations: this only clears the specific backing array for this string variable.
// Copies made by concatenation, fmt.Sprintf, or slice operations are NOT affected.
// Despite this, zeroing the primary copy is valuable because it clears the most
// likely target for memory scanners and reduces the forensic surface area.
func ZeroString(s *string) {
	if len(*s) > 0 {
		b := unsafe.Slice(unsafe.StringData(*s), len(*s))
		clear(b)
	}
	*s = ""
}
