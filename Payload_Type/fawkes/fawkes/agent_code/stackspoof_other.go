//go:build !windows && !(linux && amd64)

package main

func initStackSpoof()   {}
func initAPISpoofing() {}
