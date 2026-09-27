//go:build windows

package vmaware

// Port of hypervisor_hook() (@implements VM::HYPERVISOR_HOOK, vmaware.hpp
// ~14994-15436).
//
// Ported: locating a "0xCC 0xCC" (double breakpoint) byte pair inside
// ntdll's executable sections (falling back to the caller's own image, like
// upstream), a sanity check that executing the original 0xCC really does
// fault, patching it to 0xC3 (RET) via VirtualProtect, and re-executing to
// see whether the CPU's view of memory still reflects the old byte (across
// every CPU the current process can run on) -- the core, highest-value part
// of the technique -- plus the final boundary-straddling-NOP execution
// check.
//
// Not ported: the ERMSB/hardware-debug-register sub-check (arming Dr0/Dr7
// via {Get,Set}ThreadContext to see whether a REP MOVSB silently swallows a
// data breakpoint) and the DR7 "GD bit" persistence check. Both require
// allocating and mutating the OS's live CONTEXT record for the current
// thread; a mistake there (a wrong field offset, a debug register left
// armed on an error path) doesn't just make this one detection wrong, it
// can leave a stray hardware breakpoint active on the thread for the rest
// of the process's life, corrupting unrelated code. That risk isn't
// something this port can validate without running on real Windows, so
// unlike the rest of this file's already-guarded (and self-contained)
// probes, it's left out rather than guessed at.

import (
	"debug/pe"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(HypervisorHook, 150, hypervisorHookTechnique)
}

var procFlushInstructionCache = procOrNil(modKernel32, "FlushInstructionCache")

func flushInstructionCache(addr uintptr, size uintptr) {
	if procFlushInstructionCache == nil {
		return
	}
	procFlushInstructionCache.Call(uintptr(windows.CurrentProcess()), addr, size)
}

// findDoubleCCInModule scans every IMAGE_SCN_MEM_EXECUTE section of the
// named, already-loaded module for a "0xCC 0xCC" byte pair, returning the
// address of the *second* 0xCC (mirroring upstream: overwriting just that
// byte with 0xC3 turns it into a bare RET).
func findDoubleCCInModule(moduleName string) uintptr {
	h, err := getModuleHandle(moduleName)
	if err != nil || h == 0 {
		return 0
	}

	var pathBuf [windows.MAX_PATH]uint16
	n, err := windows.GetModuleFileName(h, &pathBuf[0], uint32(len(pathBuf)))
	if err != nil || n == 0 {
		return 0
	}
	path := windows.UTF16ToString(pathBuf[:n])

	f, err := pe.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	const imageSCNMemExecute = 0x20000000
	base := uintptr(h)

	for _, sec := range f.Sections {
		if sec.Characteristics&imageSCNMemExecute == 0 {
			continue
		}
		if sec.VirtualSize < 2 {
			continue
		}
		secAddr := unsafe.Add(unsafe.Pointer(base), sec.VirtualAddress)
		data := unsafe.Slice((*byte)(secAddr), sec.VirtualSize)
		for j := 0; j+1 < len(data); j++ {
			if data[j] == 0xCC && data[j+1] == 0xCC {
				return uintptr(unsafe.Pointer(&data[j+1]))
			}
		}
	}
	return 0
}

// findDoubleCCInOwnImage mirrors the fallback find_double_cc lambda: scan
// the 4KB page containing an arbitrary code pointer of ours for a "0xCC
// 0xCC" pair. Go toolchain output doesn't pad functions with 0xCC the way
// MSVC/GCC debug builds do, so in practice this will usually find nothing,
// exactly like upstream's own fallback would on a binary without that
// padding.
func findDoubleCCInOwnImage() uintptr {
	anchor := reflect.ValueOf(hypervisorHookTechnique).Pointer()
	pageStart := anchor &^ 0xFFF
	data := unsafe.Slice((*byte)(unsafe.Pointer(pageStart)), 0x1000)
	for i := 0; i < 0xFFF; i++ {
		if data[i] == 0xCC && data[i+1] == 0xCC {
			return uintptr(unsafe.Pointer(&data[i+1]))
		}
	}
	return 0
}

// execAndCatch calls the given code address with no arguments and reports
// whether doing so faulted, via the same guardedAbortCall infrastructure
// every other risky-instruction probe in this port uses.
func execAndCatch(addr uintptr) bool {
	return guardedAbortCall(func() { callRaw(addr) })
}

func hypervisorHookTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	pointer := findDoubleCCInModule("ntdll.dll")
	if pointer == 0 {
		pointer = findDoubleCCInOwnImage()
		if pointer == 0 {
			return false
		}
	}

	// Executing the original 0xCC natively should fault.
	if !execAndCatch(pointer) {
		return false
	}

	originalByte := *(*byte)(unsafe.Pointer(pointer))

	var oldProtect uint32
	if err := windows.VirtualProtect(pointer, 1, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return false
	}
	*(*byte)(unsafe.Pointer(pointer)) = 0xC3
	flushInstructionCache(pointer, 1)

	var dummy uint32
	if err := windows.VirtualProtect(pointer, 1, oldProtect, &dummy); err != nil {
		*(*byte)(unsafe.Pointer(pointer)) = originalByte
		flushInstructionCache(pointer, 1)
		return false
	}

	restore := func() {
		var prevProt uint32
		if windows.VirtualProtect(pointer, 1, windows.PAGE_EXECUTE_READWRITE, &prevProt) == nil {
			*(*byte)(unsafe.Pointer(pointer)) = originalByte
			flushInstructionCache(pointer, 1)
			windows.VirtualProtect(pointer, 1, prevProt, &dummy)
		}
	}

	hookDetected := false
	if execAndCatch(pointer) {
		hookDetected = true
	} else {
		thread := currentThreadPseudoHandle
		var activeAff groupAffinity
		if getThreadGroupAffinity(thread, &activeAff) {
			anyThrew := false
			maxBits := unsafe.Sizeof(uintptr(0)) * 8
			for i := uintptr(0); i < maxBits; i++ {
				if activeAff.Mask&(uintptr(1)<<i) == 0 {
					continue
				}
				target := activeAff
				target.Mask = uintptr(1) << i
				if setThreadGroupAffinity(thread, &target) {
					if execAndCatch(pointer) {
						anyThrew = true
					}
				}
			}
			setThreadGroupAffinity(thread, &activeAff)
			if anyThrew {
				hookDetected = true
			}
		}
	}

	restore()

	if hookDetected {
		return true
	}

	return hypervisorHookBoundaryStraddle()
}

// hypervisorHookBoundaryStraddle mirrors hypervisor_hook()'s final check:
// place a multi-byte NOP that straddles a 4KB page boundary (with the two
// pages given different memory protections) and see whether executing it
// faults, which some emulators/hypervisors do when an instruction spans two
// distinct EPT/NPT leaf entries.
func hypervisorHookBoundaryStraddle() bool {
	size := uintptr(0x2000)
	base, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil || base == 0 {
		return false
	}
	defer windows.VirtualFree(base, 0, windows.MEM_RELEASE)

	page0 := unsafe.Pointer(base)
	page1 := unsafe.Add(page0, 0x1000)

	page0Bytes := []byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F}
	page1Bytes := []byte{0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3}

	copy(unsafe.Slice((*byte)(unsafe.Add(page0, 0xFF8)), len(page0Bytes)), page0Bytes)
	copy(unsafe.Slice((*byte)(page1), len(page1Bytes)), page1Bytes)

	var oldProtect uint32
	windows.VirtualProtect(uintptr(page1), 0x1000, windows.PAGE_EXECUTE_READ, &oldProtect)
	flushInstructionCache(base, size)

	faulted := execAndCatch(uintptr(unsafe.Add(page0, 0xFF8)))
	return faulted
}
