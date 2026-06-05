//go:build linux && arm64

package commands

const sysMemfdCreate = 279

func elfMachine() uint16 { return 0xB7 } // EM_AARCH64
