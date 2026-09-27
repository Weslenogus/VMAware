package cpuprobe

import (
	"strings"
	"sync"
)

// CPUID mirrors VM::cpu::cpuid(a,b,c,d,a_leaf) — note the C++ default
// argument for the subleaf is 0xFF, not 0; every call site that matters
// here (basic_info, features, hypervisor leaves, brand leaves, func_ext,
// the AMD easter-egg leaf) ignores ECX-as-subleaf entirely, so this is
// behaviorally identical to passing 0, but it's kept as 0xFF for an exact
// match against the source.
func CPUID(leaf uint32) (eax, ebx, ecx, edx uint32) {
	return rawCPUID(leaf, 0xFF)
}

// CPUIDSub mirrors VM::cpu::cpuid(a,b,c,d,a_leaf,c_leaf) with an explicit
// subleaf, used by leaves that need one (e.g. extended topology leaves 0xB
// / 0x1F, or extended features leaf 7 subleaf 0).
func CPUIDSub(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32) {
	return rawCPUID(leaf, subleaf)
}

var leafCache = struct {
	mu sync.Mutex
	m  map[uint32]bool
}{m: make(map[uint32]bool)}

// IsLeafSupported mirrors VM::cpu::is_leaf_supported.
func IsLeafSupported(leaf uint32) bool {
	leafCache.mu.Lock()
	if v, ok := leafCache.m[leaf]; ok {
		leafCache.mu.Unlock()
		return v
	}
	leafCache.mu.Unlock()

	var supported bool
	switch {
	case leaf < LeafHypervisor:
		eax, _, _, _ := CPUID(LeafBasicInfo)
		supported = leaf <= eax
	case leaf < LeafFuncExt:
		eax, _, _, _ := CPUID(LeafHypervisor)
		supported = leaf <= eax
	case leaf < 0xC0000000:
		eax, _, _, _ := CPUID(LeafFuncExt)
		supported = leaf <= eax
	default:
		supported = false
	}

	leafCache.mu.Lock()
	leafCache.m[leaf] = supported
	leafCache.mu.Unlock()

	return supported
}

// IsAMD mirrors VM::cpu::is_amd(): "AuthenticAMD" / the earlier "AMDisbetter!"
// signature, both carried in the leaf-0 ECX register.
func IsAMD() bool {
	const authenticAMDECX = 0x444d4163 // "cAMD"
	const amdIsBetterECX = 0x21726574  // "ter!"

	_, _, ecx, _ := CPUID(LeafBasicInfo)
	return ecx == authenticAMDECX || ecx == amdIsBetterECX
}

// IsIntel mirrors VM::cpu::is_intel(): "GenuineIntel", plus the rare
// "GenuineIotel" manufacturer string some Intel CPUs report.
func IsIntel() bool {
	const intelECX1 = 0x6c65746e // "ntel"
	const intelECX2 = 0x6c65746f // "otel"

	_, _, ecx, _ := CPUID(LeafBasicInfo)
	return ecx == intelECX1 || ecx == intelECX2
}

var brandCache struct {
	mu     sync.Mutex
	cached bool
	value  string
}

// GetBrand mirrors VM::cpu::get_brand(): reads the raw 48-byte brand string
// across leaves 0x80000002-4 and left-trims it only (trailing spaces are
// left intact on purpose — BOCHS_CPU and THREAD_MISMATCH match against
// brand strings that upstream Intel/AMD CPUs pad with trailing spaces).
func GetBrand() string {
	brandCache.mu.Lock()
	if brandCache.cached {
		v := brandCache.value
		brandCache.mu.Unlock()
		return v
	}
	brandCache.mu.Unlock()

	if !IsLeafSupported(LeafBrand3) {
		return "Unknown"
	}

	var regs [12]uint32
	regs[0], regs[1], regs[2], regs[3] = CPUID(LeafBrand1)
	regs[4], regs[5], regs[6], regs[7] = CPUID(LeafBrand2)
	regs[8], regs[9], regs[10], regs[11] = CPUID(LeafBrand3)

	buf := make([]byte, 48)
	for i, r := range regs {
		buf[i*4+0] = byte(r)
		buf[i*4+1] = byte(r >> 8)
		buf[i*4+2] = byte(r >> 16)
		buf[i*4+3] = byte(r >> 24)
	}

	// Left-trim only (mirrors string::ltrim), then cut at the first NUL —
	// the C++ side treats the 48-byte buffer as a NUL-terminated C string.
	trimmed := strings.TrimLeft(string(buf), " \t\n\v\f\r")
	if idx := strings.IndexByte(trimmed, 0); idx >= 0 {
		trimmed = trimmed[:idx]
	}

	brandCache.mu.Lock()
	brandCache.cached = true
	brandCache.value = trimmed
	brandCache.mu.Unlock()

	return trimmed
}

var manufacturerCache = struct {
	mu sync.Mutex
	m  map[uint32]string
}{m: make(map[uint32]string)}

// CPUManufacturer mirrors VM::cpu::cpu_manufacturer(leafID): the raw
// (EBX, ECX, EDX) ASCII vendor string reported by a hypervisor CPUID leaf.
// Only LeafHypervisor and LeafHvEnlightenment are valid; anything else
// returns "".
func CPUManufacturer(leafID uint32) string {
	if leafID != LeafHypervisor && leafID != LeafHvEnlightenment {
		return ""
	}

	manufacturerCache.mu.Lock()
	if v, ok := manufacturerCache.m[leafID]; ok {
		manufacturerCache.mu.Unlock()
		return v
	}
	manufacturerCache.mu.Unlock()

	_, ebx, ecx, edx := CPUID(leafID)

	var value string
	if ebx != 0 || ecx != 0 || edx != 0 {
		buf := make([]byte, 12)
		regs := [3]uint32{ebx, ecx, edx}
		for i, r := range regs {
			buf[i*4+0] = byte(r)
			buf[i*4+1] = byte(r >> 8)
			buf[i*4+2] = byte(r >> 16)
			buf[i*4+3] = byte(r >> 24)
		}
		if idx := strings.IndexByte(string(buf), 0); idx >= 0 {
			value = string(buf[:idx])
		} else {
			value = string(buf)
		}
	}

	manufacturerCache.mu.Lock()
	manufacturerCache.m[leafID] = value
	manufacturerCache.mu.Unlock()

	return value
}

// SteppingInfo mirrors VM::cpu::stepping_struct.
type SteppingInfo struct {
	Model    uint8
	Family   uint8
	ExtModel uint8
}

// FetchSteppings mirrors VM::cpu::fetch_steppings.
func FetchSteppings() SteppingInfo {
	eax, _, _, _ := CPUID(LeafFeatures)
	return SteppingInfo{
		Model:    uint8((eax >> 4) & 0b1111),
		Family:   uint8((eax >> 8) & 0b1111),
		ExtModel: uint8((eax >> 16) & 0b1111),
	}
}

// IsCeleron mirrors VM::cpu::is_celeron.
func IsCeleron(steps SteppingInfo) bool {
	if !IsIntel() {
		return false
	}
	const celeronModel, celeronFamily, celeronExtModel = 0xA, 0x6, 0x2
	return steps.Model == celeronModel && steps.Family == celeronFamily && steps.ExtModel == celeronExtModel
}
