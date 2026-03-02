package main

import (
	_ "embed"
	"runtime"
)

//go:embed padding.bin
var paddingData []byte

//go:noinline
func usePadding() {
	// runtime.KeepAlive prevents the compiler from stripping the embedded blob.
	// The blank identifier approach (_ = paddingData[0]) gets optimized away
	// by Go 1.25's dead code elimination. KeepAlive is a runtime intrinsic
	// that the compiler cannot remove.
	runtime.KeepAlive(paddingData)
}
