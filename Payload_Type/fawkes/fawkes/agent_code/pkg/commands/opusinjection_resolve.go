//go:build windows
// +build windows

package commands

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ctrlHandlerOffsets struct {
	handlerList     uintptr // RVA of pointer to handler array
	length          uintptr // RVA of current handler count (DWORD)
	allocatedLength uintptr // RVA of allocated capacity (DWORD)
}

var (
	resolveOnce    sync.Once
	resolvedResult ctrlHandlerOffsets
	resolvedErr    error
)

func getCtrlHandlerOffsets() (ctrlHandlerOffsets, error) {
	resolveOnce.Do(func() {
		resolvedResult, resolvedErr = scanSetConsoleCtrlHandler()
	})
	return resolvedResult, resolvedErr
}

func scanSetConsoleCtrlHandler() (ctrlHandlerOffsets, error) {
	kb := windows.NewLazySystemDLL("kernelbase.dll")
	if err := kb.Load(); err != nil {
		return ctrlHandlerOffsets{}, fmt.Errorf("load kernelbase.dll: %w", err)
	}
	kbBase := uintptr(kb.Handle())

	proc := kb.NewProc("SetConsoleCtrlHandler")
	if err := proc.Find(); err != nil {
		return ctrlHandlerOffsets{}, fmt.Errorf("find SetConsoleCtrlHandler: %w", err)
	}
	funcAddr := proc.Addr()

	const scanLen = 512
	code := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), scanLen)

	type ripRef struct {
		rva    uintptr
		pos    int
		is64   bool
		opcode byte
	}

	var refs []ripRef

	for pos := 0; pos < scanLen-7; pos++ {
		cursor := pos

		hasREX := code[cursor] >= 0x40 && code[cursor] <= 0x4F
		rexW := hasREX && (code[cursor]&0x08) != 0
		if hasREX {
			cursor++
		}
		if cursor+5 >= scanLen {
			continue
		}

		opcode := code[cursor]
		cursor++
		modrm := code[cursor]
		cursor++

		if modrm&0xC7 != 0x05 {
			continue
		}

		instrEnd := 0
		switch opcode {
		case 0x8D, 0x8B, 0x89, 0x3B, 0x39:
			instrEnd = cursor + 4
		case 0x83:
			instrEnd = cursor + 4 + 1
		default:
			continue
		}

		if instrEnd > scanLen {
			continue
		}

		disp := int32(code[cursor]) |
			int32(code[cursor+1])<<8 |
			int32(code[cursor+2])<<16 |
			int32(code[cursor+3])<<24

		nextInstrAddr := funcAddr + uintptr(instrEnd)
		targetAddr := uintptr(int64(nextInstrAddr) + int64(disp))
		targetRVA := targetAddr - kbBase

		refs = append(refs, ripRef{
			rva:    targetRVA,
			pos:    pos,
			is64:   rexW,
			opcode: opcode,
		})
	}

	if len(refs) < 3 {
		return ctrlHandlerOffsets{}, fmt.Errorf("only %d RIP-relative refs found (need >=3)", len(refs))
	}

	var result ctrlHandlerOffsets
	found := false

	for i := 0; i < len(refs) && !found; i++ {
		for j := i + 1; j < len(refs); j++ {
			diff := int64(refs[j].rva) - int64(refs[i].rva)
			if diff == 4 {
				result.length = refs[i].rva
				result.allocatedLength = refs[j].rva
				found = true
				break
			} else if diff == -4 {
				result.length = refs[j].rva
				result.allocatedLength = refs[i].rva
				found = true
				break
			}
		}
	}
	if !found {
		return ctrlHandlerOffsets{}, fmt.Errorf("no adjacent DWORD pair found in SetConsoleCtrlHandler")
	}

	lenAddr := kbBase + result.length
	allocAddr := kbBase + result.allocatedLength
	localLen := *(*uint32)(unsafe.Pointer(lenAddr))
	localAlloc := *(*uint32)(unsafe.Pointer(allocAddr))
	if localLen == 0 || localLen > 256 || localAlloc < localLen || localAlloc > 4096 {
		return ctrlHandlerOffsets{}, fmt.Errorf(
			"handler count validation failed: length=%d, allocated=%d", localLen, localAlloc)
	}

	for _, ref := range refs {
		if ref.rva == result.length || ref.rva == result.allocatedLength {
			continue
		}
		if ref.pos == refs[0].pos {
			continue
		}
		candidateAddr := kbBase + ref.rva
		candidateVal := *(*uintptr)(unsafe.Pointer(candidateAddr))
		if candidateVal != 0 && candidateVal&0x7 == 0 && candidateVal < 0x7FFFFFFFFFFF {
			result.handlerList = ref.rva
			break
		}
	}

	if result.handlerList == 0 {
		return ctrlHandlerOffsets{}, fmt.Errorf("could not identify HandlerList pointer")
	}

	return result, nil
}
