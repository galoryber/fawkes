package main

import (
	_ "embed"
)

//go:embed padding.bin
var paddingData []byte

func usePadding() {
	// Reference paddingData to prevent the compiler from stripping the embedded blob.
	// No output — avoid any console IOC on the target.
	if len(paddingData) > 0 {
		_ = paddingData[0]
	}
}
