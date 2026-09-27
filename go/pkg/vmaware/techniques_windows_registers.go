//go:build windows

package vmaware

// Port of the Windows branch of system_registers() (@implements
// VM::SYSTEM_REGISTERS, vmaware.hpp ~9267-9524) and azure() (@implements
// VM::AZURE, vmaware.hpp ~9553-9581).

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(SystemRegisters, 50, systemRegistersTechnique)
	RegisterTechnique(Azure, 30, azureTechnique)
}

// groupAffinity (GROUP_AFFINITY) is defined in thread_smt_windows.go and
// reused here.

var (
	procGetThreadGroupAffinity = procOrNil(modKernel32, "GetThreadGroupAffinity")
	procSetThreadGroupAffinity = procOrNil(modKernel32, "SetThreadGroupAffinity")
)

// currentThreadPseudoHandle mirrors reinterpret_cast<HANDLE>(-2), the
// GetCurrentThread() pseudo handle.
var currentThreadPseudoHandle = windows.Handle(^uintptr(1))

func getThreadGroupAffinity(h windows.Handle, out *groupAffinity) bool {
	if procGetThreadGroupAffinity == nil {
		return false
	}
	r1, _, _ := procGetThreadGroupAffinity.Call(uintptr(h), uintptr(unsafe.Pointer(out)))
	return r1 != 0
}

func setThreadGroupAffinity(h windows.Handle, in *groupAffinity) bool {
	if procSetThreadGroupAffinity == nil {
		return false
	}
	r1, _, _ := procSetThreadGroupAffinity.Call(uintptr(h), uintptr(unsafe.Pointer(in)), 0)
	return r1 != 0
}

func systemRegistersTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	found := false
	thread := currentThreadPseudoHandle

	var originalAff groupAffinity
	if getThreadGroupAffinity(thread, &originalAff) {
		maxBits := unsafe.Sizeof(uintptr(0)) * 8
		for i := uintptr(0); i < maxBits && !found; i++ {
			if originalAff.Mask&(uintptr(1)<<i) == 0 {
				continue
			}
			target := originalAff
			target.Mask = uintptr(1) << i
			if !setThreadGroupAffinity(thread, &target) {
				continue
			}

			// Technique 1: SGDT (x86 & x64).
			gdtr := make([]byte, 10)
			sgdtFaulted := guardedAbortCall(func() { sgdtProbe(&gdtr[0]) })
			if !sgdtFaulted {
				gdtBase := gdtBaseFromDescriptor(gdtr)
				if (gdtBase>>24)&0xFF == 0xFF {
					found = true
				}
			}

			// Technique 2: SLDT (x86_32 only).
			if !found {
				found = systemRegistersSLDT()
			}

			// Technique 3: SIDT (x86 & x64).
			if !found {
				idtr := make([]byte, 10)
				sidtFaulted := guardedAbortCall(func() { sidtProbe(&idtr[0]) })
				if !sidtFaulted {
					idtBase := gdtBaseFromDescriptor(idtr)
					if (idtBase>>24)&0xFF == 0xE8 {
						AddWithScore(BrandVPC, 100)
						found = true
					}
				}
			}
		}

		setThreadGroupAffinity(thread, &originalAff)
	}

	// Technique 4: SMSW (x86_32 only), no affinity pinning needed.
	if !found {
		found = systemRegistersSMSW()
	}

	return found
}

// gdtBaseFromDescriptor extracts the base-address field from a raw
// SGDT/SIDT descriptor buffer: a 2-byte limit followed by the base (4 bytes
// on 386, 8 on amd64).
func gdtBaseFromDescriptor(buf []byte) uint64 {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return le64(buf[2:10])
	}
	return uint64(le32(buf[2:6]))
}

func le64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// --- Azure (@implements VM::AZURE) ----------------------------------------

func azureTechnique() bool {
	var buf [16]uint16 // MAX_COMPUTERNAME_LENGTH+1
	n := uint32(len(buf))
	if err := windows.GetComputerName(&buf[0], &n); err != nil {
		return false
	}
	if n != 13 {
		return false
	}
	name := windows.UTF16ToString(buf[:n])

	if !strings.HasPrefix(name, "runnervm") {
		return false
	}

	isMatch := true
	for i := 8; i <= 12; i++ {
		c := name[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			isMatch = false
			break
		}
	}

	if isMatch {
		return Add(BrandAzureHyperV)
	}
	return false
}
