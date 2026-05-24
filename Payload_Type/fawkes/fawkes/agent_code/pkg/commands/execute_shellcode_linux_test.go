//go:build linux

package commands

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestExecuteShellcodeLinux_Name(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	if got := cmd.Name(); got != "execute-shellcode" {
		t.Errorf("Name() = %q, want %q", got, "execute-shellcode")
	}
}

func TestExecuteShellcodeLinux_EmptyParams(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("Empty params should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcodeLinux_EmptyShellcode(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcodeLinux_InvalidBase64(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: "not-valid-base64!!!"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcodeLinux_EmptyAfterDecode(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{})})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty decoded shellcode should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcodeLinux_NopRet(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	// x86_64 NOP + RET: safe to execute, returns immediately
	nopRet := []byte{0x90, 0xC3}
	b64 := base64.StdEncoding.EncodeToString(nopRet)
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: b64})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("NOP+RET shellcode should succeed, got status=%q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "mmap") {
		t.Error("output should mention mmap method")
	}
	if !strings.Contains(result.Output, "0x") {
		t.Error("output should contain hex address")
	}
}

func TestExecuteShellcodeLinux_ParamParsing(t *testing.T) {
	input := `{"shellcode_b64":"AQID"}`
	var args executeShellcodeArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if args.ShellcodeB64 != "AQID" {
		t.Errorf("ShellcodeB64 = %q, want %q", args.ShellcodeB64, "AQID")
	}
}

func TestExecuteShellcodeLinux_InvalidJSON(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcodeLinux_TechniqueDefault(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	nopRet := base64.StdEncoding.EncodeToString([]byte{0x90, 0xC3})
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"` + nopRet + `"}`})
	if result.Status != "success" {
		t.Fatalf("Default technique should succeed, got status=%q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "mmap RW") {
		t.Errorf("Default technique should be mmap, got %q", result.Output)
	}
}

func TestExecuteShellcodeLinux_TechniqueMmap(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	nopRet := base64.StdEncoding.EncodeToString([]byte{0x90, 0xC3})
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"` + nopRet + `","technique":"mmap"}`})
	if result.Status != "success" {
		t.Fatalf("mmap technique should succeed, got status=%q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "mmap RW") {
		t.Errorf("mmap output should mention mmap RW, got %q", result.Output)
	}
}

func TestExecuteShellcodeLinux_TechniqueMemfd(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	nopRet := base64.StdEncoding.EncodeToString([]byte{0x90, 0xC3})
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"` + nopRet + `","technique":"memfd"}`})
	if result.Status != "success" {
		t.Fatalf("memfd technique should succeed, got status=%q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "memfd") {
		t.Errorf("memfd output should mention memfd, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "fd-backed") {
		t.Errorf("memfd output should mention fd-backed, got %q", result.Output)
	}
}

func TestExecuteShellcodeLinux_TechniqueInvalid(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	nopRet := base64.StdEncoding.EncodeToString([]byte{0x90, 0xC3})
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"` + nopRet + `","technique":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("Invalid technique should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown technique") {
		t.Errorf("Output should mention unknown technique, got %q", result.Output)
	}
}

func TestExecuteShellcodeLinux_TechniqueParsing(t *testing.T) {
	input := `{"shellcode_b64":"AQID","technique":"memfd"}`
	var args executeShellcodeArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if args.Technique != "memfd" {
		t.Errorf("Technique = %q, want memfd", args.Technique)
	}
}

func TestExecuteShellcodeLinux_MemfdEmptyShellcode(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	empty := base64.StdEncoding.EncodeToString([]byte{})
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"` + empty + `","technique":"memfd"}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode with memfd should error, got status=%q", result.Status)
	}
}

func TestShellcodeTechniqueHelp(t *testing.T) {
	help := ShellcodeTechniqueHelp()
	if !strings.Contains(help, "mmap") || !strings.Contains(help, "memfd") {
		t.Errorf("Help should list both techniques, got %q", help)
	}
}
