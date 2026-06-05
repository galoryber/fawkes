//go:build !windows && !(linux && amd64)

package commands

import "time"

func InitStackSpoof() error     { return nil }
func StackSpoofAvailable() bool { return false }
func StackSpoofSleep(d time.Duration) { time.Sleep(d) }
func CleanupStackSpoof()        {}
