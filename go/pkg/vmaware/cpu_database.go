package vmaware

import (
	"strings"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

// cpuEntrySource is the raw {model substring, threads, smt} tuple exactly as
// vmaware.hpp's cpu_entry tables have it (cpu_database_intel.go /
// cpu_database_amd.go). Keeping the substring around only here (rather than
// in cpuEntry) mirrors how cpu_entry's constexpr constructor consumes `m`
// once, at construction, to derive `hash` -- the substring itself isn't part
// of the runtime struct upstream, and thread_mismatch never re-hashes these
// tables.
type cpuEntrySource struct {
	model   string
	threads uint8
	smt     bool
}

// cpuEntry mirrors VM::cpu::cpu_entry.
type cpuEntry struct {
	hash    uint32
	threads uint8
	smt     bool
}

// buildCPUEntries mirrors what cpu_entry's constexpr constructor does for
// every element of a get_intel_*_db/get_amd_ryzen_db array at compile time:
// hash the model substring once and keep only {hash, threads, smt} around.
func buildCPUEntries(src []cpuEntrySource) []cpuEntry {
	out := make([]cpuEntry, len(src))
	for i, e := range src {
		out[i] = cpuEntry{hash: crc32VMAware(e.model), threads: e.threads, smt: e.smt}
	}
	return out
}

// intelCoreDB/intelXeonDB/intelUltraDB/amdRyzenDB mirror the pointer+size
// pairs get_intel_core_db/get_intel_xeon_db/get_intel_ultra_db/
// get_amd_ryzen_db hand back in the C++ source; thread_mismatch (in
// techniques_cpu.go) picks one of these exactly like it picks a
// {db, db_size} pair there.
var (
	intelCoreDB  []cpuEntry
	intelXeonDB  []cpuEntry
	intelUltraDB []cpuEntry
	amdRyzenDB   []cpuEntry
)

func init() {
	intelCoreDB = buildCPUEntries(intelCoreDBSource)
	intelXeonDB = buildCPUEntries(intelXeonDBSource)
	intelUltraDB = buildCPUEntries(intelUltraDBSource)
	amdRyzenDB = buildCPUEntries(amdRyzenDBSource)
}

// crc32Bits mirrors VM::cpu::constexpr_hash::crc32_bits: 8 rounds of a
// bit-reflected CRC32-C (Castagnoli, polynomial 0x82F63B78) mixing step,
// applied to a byte that's first XORed into the running crc. This is
// exactly the same single-byte step as util::hash::crc32c_byte_sw
// (crc32c_bit_step unrolled 8 times over crc ^ byte) -- the two C++
// functions are algorithmically identical, and thread_mismatch's live
// lookup (techniques_cpu.go) actually calls the util::hash version, not
// constexpr_hash, to build its running hash one character at a time. One Go
// helper faithfully covers both call sites.
func crc32Bits(crc uint32, b byte) uint32 {
	crc ^= uint32(b)
	for i := 0; i < 8; i++ {
		if crc&1 != 0 {
			crc = (crc >> 1) ^ 0x82F63B78
		} else {
			crc >>= 1
		}
	}
	return crc
}

// crc32VMAware mirrors VM::cpu::constexpr_hash::get (crc32_str with crc=0):
// every byte of s folded in, in order, starting from crc=0.
func crc32VMAware(s string) uint32 {
	var crc uint32
	for i := 0; i < len(s); i++ {
		crc = crc32Bits(crc, s[i])
	}
	return crc
}

// modelStruct mirrors VM::cpu::model_struct.
type modelStruct struct {
	found     bool
	isXeon    bool
	isISeries bool
	isRyzen   bool
	str       string
}

// getModel mirrors VM::cpu::get_model() (vmaware.hpp lines 1444-1490).
func getModel() modelStruct {
	brand := cpuprobe.GetBrand()

	var result modelStruct
	if brand == "" {
		return result
	}

	if cpuprobe.IsIntel() {
		// Ultra
		if strings.Contains(brand, "Ultra") && strings.ContainsAny(brand, "0123456789") {
			result.found = true
			result.str = brand
			return result
		}

		// I-series
		if strings.ContainsRune(brand, 'i') &&
			strings.ContainsRune(brand, '-') &&
			strings.ContainsAny(brand, "0123456789") {
			result.found = true
			result.isISeries = true
			result.str = brand
			return result
		}

		// Xeon
		if strings.ContainsAny(brand, "DEW") &&
			strings.ContainsRune(brand, '-') &&
			strings.ContainsAny(brand, "0123456789") {
			result.found = true
			result.isXeon = true
			result.str = brand
			return result
		}
	} else if cpuprobe.IsAMD() {
		if strings.Contains(brand, "AMD Ryzen") {
			result.found = true
			result.isRyzen = true
			result.str = brand
			return result
		}
	}

	return result
}
