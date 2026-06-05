//go:build linux && amd64

package commands

const sysMemfdCreate = 319

func elfMachine() uint16 { return 0x3E } // EM_X86_64
