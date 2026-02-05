package main

import (
	_ "embed"
	"fmt"
)

//go:embed padding.bin
var paddingData []byte

func usePadding() {
	if len(paddingData) > 1 {
		fmt.Printf("Loaded %d bytes of padding data.\n", len(paddingData))
		for i, b := range paddingData {
			_ = b
			if i >= 255 {
				break
			}
		}
	}
}
