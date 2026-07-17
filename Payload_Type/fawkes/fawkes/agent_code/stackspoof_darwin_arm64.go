//go:build darwin && arm64

package main

import "fawkes/pkg/commands"

func initStackSpoof() {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	_ = commands.InitStackSpoof()
}

func initAPISpoofing() {}
