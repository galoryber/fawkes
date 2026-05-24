//go:build linux && amd64

package commands

func init() {
	RegisterCommand(&PtraceInjectCommand{})
	RegisterCommand(&VanillaInjectionCommand{})
	RegisterCommand(&HollowingCommand{})
}
