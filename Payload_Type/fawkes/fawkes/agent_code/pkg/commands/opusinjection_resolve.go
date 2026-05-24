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

type ripRef struct {
	rva    uintptr
	pos    int
	is64   bool
	opcode byte
}

// scanSetConsoleCtrlHandler scans SetConsoleCtrlHandler (and its internal
// AddConsoleHandler subroutine) for RIP-relative references to the three
// global variables we need: HandlerList, HandlerListLength, and
// AllocatedHandlerListLength.
//
// On Win11 23H2 the exported function is a short wrapper that calls an
// internal function ~0xBC bytes in. The actual MOV/CMP pattern for
// Length vs AllocatedLength lives in that internal function at ~0xCB-0xD4.
// The two DWORDs are 20 bytes apart on 23H2 (not 4 as on older builds),
// so we use instruction-type matching instead of adjacency.
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

	const scanLen = 1024
	code := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), scanLen)

	refs := collectRIPRelativeRefs(code, funcAddr, kbBase, scanLen)

	if len(refs) < 3 {
		return ctrlHandlerOffsets{}, fmt.Errorf("only %d RIP-relative refs found (need >=3)", len(refs))
	}

	result, err := identifyOffsets(refs, kbBase)
	if err != nil {
		return ctrlHandlerOffsets{}, err
	}

	if err := validateOffsets(result, kbBase); err != nil {
		return ctrlHandlerOffsets{}, err
	}

	return result, nil
}

func collectRIPRelativeRefs(code []byte, funcAddr, kbBase uintptr, scanLen int) []ripRef {
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

		// RIP-relative: mod=00, rm=101 → modrm & 0xC7 == 0x05
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

	return refs
}

// identifyOffsets finds Length, AllocatedLength, and HandlerList from the
// collected RIP-relative references using instruction-type patterns:
//   - Length: first 32-bit MOV load (0x8B, no REX.W) after offset 0x80
//   - AllocatedLength: first 32-bit CMP (0x3B, no REX.W) after Length
//   - HandlerList: first 64-bit MOV load (REX.W + 0x8B) after Length
//     that references a different address than Length/AllocatedLength
func identifyOffsets(refs []ripRef, kbBase uintptr) (ctrlHandlerOffsets, error) {
	var result ctrlHandlerOffsets

	// Skip the wrapper prologue — the internal function starts around 0xB0-0xC0.
	// Look for the first 32-bit MOV load after offset 0x80.
	lengthIdx := -1
	for i, ref := range refs {
		if ref.pos < 0x80 {
			continue
		}
		if ref.opcode == 0x8B && !ref.is64 {
			result.length = ref.rva
			lengthIdx = i
			break
		}
	}
	if lengthIdx < 0 {
		return ctrlHandlerOffsets{}, fmt.Errorf("could not find HandlerListLength (no 32-bit MOV load after offset 0x80)")
	}

	// AllocatedLength: first 32-bit CMP (0x3B or 0x39) after the Length ref
	for i := lengthIdx + 1; i < len(refs); i++ {
		ref := refs[i]
		if (ref.opcode == 0x3B || ref.opcode == 0x39) && !ref.is64 {
			result.allocatedLength = ref.rva
			break
		}
	}
	if result.allocatedLength == 0 {
		return ctrlHandlerOffsets{}, fmt.Errorf("could not find AllocatedHandlerListLength (no 32-bit CMP after Length)")
	}

	// HandlerList: first 64-bit MOV load (REX.W + 0x8B) after the Length ref
	// that targets a different address.
	for i := lengthIdx + 1; i < len(refs); i++ {
		ref := refs[i]
		if ref.opcode == 0x8B && ref.is64 && ref.rva != result.length && ref.rva != result.allocatedLength {
			result.handlerList = ref.rva
			break
		}
	}
	if result.handlerList == 0 {
		return ctrlHandlerOffsets{}, fmt.Errorf("could not find HandlerList pointer (no 64-bit MOV load after Length)")
	}

	return result, nil
}

func validateOffsets(result ctrlHandlerOffsets, kbBase uintptr) error {
	lenAddr := kbBase + result.length
	allocAddr := kbBase + result.allocatedLength
	listAddr := kbBase + result.handlerList

	localLen := *(*uint32)(unsafe.Pointer(lenAddr))
	localAlloc := *(*uint32)(unsafe.Pointer(allocAddr))

	if localLen == 0 || localLen > 256 || localAlloc < localLen || localAlloc > 4096 {
		return fmt.Errorf(
			"handler count validation failed: length=%d, allocated=%d (RVAs: len=0x%X, alloc=0x%X)",
			localLen, localAlloc, result.length, result.allocatedLength)
	}

	listVal := *(*uintptr)(unsafe.Pointer(listAddr))
	if listVal == 0 || listVal&0x7 != 0 || listVal > 0x7FFFFFFFFFFF {
		return fmt.Errorf(
			"handler list pointer validation failed: value=0x%X (RVA: 0x%X)",
			listVal, result.handlerList)
	}

	return nil
}
