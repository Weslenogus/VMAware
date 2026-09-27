//go:build windows

package vmaware

// Port of cpu_heuristic() (@implements VM::CPU_HEURISTIC, vmaware.hpp
// ~14165-14746) and msr() (@implements VM::MSR, vmaware.hpp ~14748-14953).
//
// Both rely on seh_windows.go's guardedAbortCall to reproduce the upstream
// __try/__except (or RtlAddVectoredExceptionHandler) protection around a
// single deliberately risky instruction. See that file's header comment.
//
// cpu_heuristic()'s AVX-512 probe is intentionally not ported (see the
// amd64-only cpuHeuristicAESAVX implementation below for why); every other
// sub-check (AES-NI, AVX, AVX2, the AMD/Intel CLZERO cross-check, and the
// PCI-chipset-vendor cross-check) is ported in full.

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

func init() {
	RegisterTechnique(CPUHeuristic, 90, cpuHeuristicTechnique)
	RegisterTechnique(MSR, 100, msrTechnique)
}

func cpuHeuristicTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	if cpuHeuristicAESAVX() {
		return true
	}

	if cpuHeuristicVendorCLZERO() {
		return true
	}

	return cpuHeuristicMotherboardVendor()
}

// cpuHeuristicMotherboardVendor mirrors cpu_heuristic()'s detect_motherboard
// lambda plus the switch that follows it: if the claimed CPU vendor
// disagrees with the PCI chipset's apparent vendor (counted by VID_8086
// "Intel" vs. VID_1022/VID_1002 "AMD" hit counts across every enumerated PCI
// device), that's spoofing.
func cpuHeuristicMotherboardVendor() bool {
	claimedAMD := cpuprobe.IsAMD()
	claimedIntel := cpuprobe.IsIntel()

	devInfo, err := windows.SetupDiGetClassDevsEx(nil, "PCI", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return false
	}
	defer windows.SetupDiDestroyDeviceInfoList(devInfo)

	const vidIntel = 0x8086
	const vidAMDMicro = 0x1022
	const vidAMDAti = 0x1002

	intelHits, amdHits := 0, 0
	for idx := 0; ; idx++ {
		devInfoData, err := windows.SetupDiEnumDeviceInfo(devInfo, idx)
		if err != nil {
			break
		}
		instID, err := windows.SetupDiGetDeviceInstanceId(devInfo, devInfoData)
		if err != nil || len(instID) < 12 {
			continue
		}
		// Case-insensitive "PCI\VEN_XXXX" prefix check.
		if !(instID[0]|0x20 == 'p' && instID[1]|0x20 == 'c' && instID[2]|0x20 == 'i' && instID[3] == '\\' &&
			instID[4]|0x20 == 'v' && instID[5]|0x20 == 'e' && instID[6]|0x20 == 'n' && instID[7] == '_') {
			continue
		}
		vid, ok := parseHex4(instID[8:])
		if !ok {
			continue
		}
		switch vid {
		case vidIntel:
			intelHits++
		case vidAMDMicro:
			amdHits += 2
		case vidAMDAti:
			amdHits++
		}
	}

	var vendor int // 0 = unknown, 1 = intel, 2 = amd
	if intelHits >= 3 && intelHits > amdHits*2 {
		vendor = 1
	} else if amdHits >= 3 && amdHits > intelHits*2 {
		vendor = 2
	}

	switch vendor {
	case 1:
		return claimedAMD && !claimedIntel
	case 2:
		return claimedIntel && !claimedAMD
	}
	return false
}

func parseHex4(s string) (uint32, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var val uint32
	for i := 0; i < 4; i++ {
		c := s[i]
		var nib uint32
		switch {
		case c >= '0' && c <= '9':
			nib = uint32(c - '0')
		case (c|0x20) >= 'a' && (c|0x20) <= 'f':
			nib = uint32((c|0x20)-'a') + 10
		default:
			return 0, false
		}
		val = val<<4 | nib
	}
	return val, true
}

// cpuHeuristicVendorCLZERO mirrors cpu_heuristic()'s second stage: probing
// the AMD-only CLZERO instruction to see whether a CPU claiming to be AMD
// genuinely supports it (Ryzen or newer, CPUID Fn8000_0008 EBX bit 0 set),
// and whether a CPU claiming to be Intel (or an unrecognized vendor) can
// nonetheless execute it, both of which indicate CPUID is being spoofed
// relative to the real hardware underneath.
func cpuHeuristicVendorCLZERO() bool {
	claimedAMD := cpuprobe.IsAMD()
	claimedIntel := cpuprobe.IsIntel()
	if !claimedAMD && !claimedIntel {
		return false
	}

	proceed := true
	expectException := false

	if claimedAMD {
		model := getModel()
		if !model.isRyzen {
			proceed = false
		}
		maxExtLeaf, _, _, _ := cpuprobe.CPUID(0x80000000)
		if maxExtLeaf >= 0x80000008 {
			_, ebx8, _, _ := cpuprobe.CPUID(0x80000008)
			if ebx8&1 == 0 {
				proceed = false
			}
		} else {
			proceed = false
		}
	}

	if claimedIntel || !claimedAMD {
		expectException = true
	}

	if !proceed {
		return false
	}

	const targetSize = 64
	target := make([]byte, targetSize)
	for i := range target {
		target[i] = 0xA5
	}

	faulted := guardedAbortCall(func() { clzeroProbe(uintptr(unsafe.Pointer(&target[0]))) })

	memoryAllZero := true
	for _, b := range target {
		if b != 0 {
			memoryAllZero = false
			break
		}
	}

	switch {
	case !faulted && expectException:
		// CPU claims Intel (or unknown) but CLZERO actually executed
		// (and genuinely zeroed the target), meaning the real hardware is AMD.
		return memoryAllZero
	case faulted && !expectException:
		// CPU claims AMD but CLZERO faulted as if unsupported, meaning the
		// real hardware is Intel (or another non-AMD vendor).
		return true
	case !faulted && !expectException:
		// CPU claims AMD, CLZERO executed without faulting, but did not
		// actually zero the target: a hypervisor is treating it as a NOP.
		return !memoryAllZero
	}
	return false
}

// --- MSR (@implements VM::MSR) --------------------------------------------

func msrTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	const randomMSR = 0xDEADBEEF

	readFaulted := guardedAbortCall(func() { rdmsrProbe(randomMSR) })
	if !readFaulted {
		return true
	}

	writeFaulted := guardedAbortCall(func() { wrmsrProbe(randomMSR, 0, 0) })
	if !writeFaulted {
		return true
	}

	return false
}
