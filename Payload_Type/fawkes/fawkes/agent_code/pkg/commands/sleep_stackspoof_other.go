//go:build !windows

package commands

import "time"

func InitStackSpoof() error     { return nil }
func StackSpoofAvailable() bool { return false }
func StackSpoofSleep(d time.Duration) { time.Sleep(d) }
func CleanupStackSpoof()        {}
