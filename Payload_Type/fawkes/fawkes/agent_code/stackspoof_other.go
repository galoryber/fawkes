//go:build !windows && !(linux && amd64) && !(darwin && arm64)

package main

func initStackSpoof()   {}
func initAPISpoofing() {}
