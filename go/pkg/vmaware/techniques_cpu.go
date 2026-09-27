package vmaware

import (
	"runtime"
	"strings"
	"sync"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

func init() {
	RegisterTechnique(ThreadMismatch, 45, threadMismatch)
	RegisterTechnique(CPUIDSignature, 95, cpuidSignature)
	RegisterTechnique(KGTSignature, 80, intelKgtSignature)
	RegisterTechnique(Timer, 45, timer)
}

// cpuDBType mirrors VM::cpu::cpu_type.
type cpuDBType uint8

const (
	cpuDBUnknown cpuDBType = iota
	cpuDBIntelI
	cpuDBIntelXeon
	cpuDBIntelUltra
	cpuDBAMD
)

// cpuThreadCountOnce/cpuThreadCountCache are named distinctly from the
// (Linux-only) ThreadCount technique's own memo::thread_count cache, even
// though both mirror the exact same C++ singleton (VM::memo::thread_count),
// to avoid a package-level redeclaration between this cross-platform file
// and that GOOS-tagged one.
var (
	cpuThreadCountOnce  sync.Once
	cpuThreadCountCache uint32
)

// fetchThreadCount mirrors VM::memo::thread_count::fetch(): the number of
// logical processors visible to this process, cached after the first call
// exactly like the C++ static local. hardware_concurrency() == 0 falls back
// to 1 upstream; runtime.NumCPU() never reports 0, but the same fallback is
// kept here for an exact mirror.
func fetchThreadCount() uint32 {
	cpuThreadCountOnce.Do(func() {
		hw := runtime.NumCPU()
		if hw <= 0 {
			hw = 1
		}
		cpuThreadCountCache = uint32(hw)
	})
	return cpuThreadCountCache
}

func isAlnumByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isModelTokenByte(c byte) bool {
	return isAlnumByte(c) || c == '-'
}

// byteAt mirrors reading str[i] on a NUL-terminated C string: out-of-range
// (including i == len(s), the Go equivalent of the terminating NUL) reads
// as the zero byte.
func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// lookupCPUEntry mirrors the hashing/lookup loop inside thread_mismatch()
// (vmaware.hpp lines ~7267-7326): walk model_name looking for runs of
// alnum/'-' characters, hashing each run incrementally byte by byte
// (lowercasing A-Z when dbType is AMD, exactly like upstream does for
// cpu_type::AMD) and checking the running hash against db every time the
// next character isn't alphanumeric (which also fires right before a '-',
// letting the token keep growing across it). Upstream's own
// "matched == nullptr || current_len > 0" guard is always true by the time
// it's reached (current_len is always >= 1 there), so it always overwrites
// matched with the latest hit -- this keeps that exact left-to-right
// "last match wins" behavior without the dead condition.
func lookupCPUEntry(modelName string, dbType cpuDBType, db []cpuEntry) *cpuEntry {
	const maxModelLen = 32

	var matched *cpuEntry

	n := len(modelName)
	for i := 0; i < n; {
		if !isAlnumByte(modelName[i]) {
			i++
			continue
		}

		var currentHash uint32
		currentLen := 0
		j := i

		for {
			k := byteAt(modelName, j)
			if !isModelTokenByte(k) {
				break
			}

			if currentLen >= maxModelLen {
				for byteAt(modelName, j) != 0 && byteAt(modelName, j) != ' ' {
					j++
				}
				break
			}

			if dbType == cpuDBAMD && k >= 'A' && k <= 'Z' {
				k += 32
			}

			currentHash = crc32Bits(currentHash, k)
			currentLen++
			j++

			if !isAlnumByte(byteAt(modelName, j)) {
				for idx := range db {
					if db[idx].hash == currentHash {
						matched = &db[idx]
					}
				}
			}
		}

		i = j
	}

	return matched
}

// threadMismatch mirrors VM::thread_mismatch (@implements VM::THREAD_MISMATCH,
// points=45). vmaware.hpp gates the whole technique behind VMAWARE_X86; this
// port has no non-x86 build target, so that guard has no Go equivalent here.
func threadMismatch() bool {
	var (
		dbType    cpuDBType
		db        []cpuEntry
		modelName string
	)

	if cpuprobe.IsIntel() {
		model := getModel()
		if model.found {
			modelName = model.str

			switch {
			case strings.Contains(modelName, "Ultra"):
				dbType = cpuDBIntelUltra
				db = intelUltraDB
			case model.isISeries:
				dbType = cpuDBIntelI
				db = intelCoreDB
			case model.isXeon:
				dbType = cpuDBIntelXeon
				db = intelXeonDB
			}
		}
	} else if cpuprobe.IsAMD() {
		dbType = cpuDBAMD
		modelName = cpuprobe.GetBrand()
		db = amdRyzenDB
	}

	if db == nil || modelName == "" {
		return false
	}

	matched := lookupCPUEntry(modelName, dbType, db)
	if matched == nil {
		return false
	}

	if matched.smt && !isSMTActive() {
		// CPU normally runs under SMT, but SMT was fully disabled in the BIOS.
		return false
	}

	actual := fetchThreadCount()
	return actual != uint32(matched.threads)
}

// cpuidSignature mirrors VM::cpuid_signature (@implements VM::CPUID_SIGNATURE,
// points=95).
func cpuidSignature() bool {
	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafHvInterface)

	const simplevisor = 0x00766853 // " vhS"

	if eax == simplevisor {
		return Add(BrandSimpleVisor)
	}

	if cpuprobe.IsIntel() {
		hasLeafB := cpuprobe.IsLeafSupported(cpuprobe.LeafExtTopology)
		hasLeaf1F := cpuprobe.IsLeafSupported(cpuprobe.LeafV2ExtTopology)

		// If neither extended topology leaf is supported, we can't perform the check.
		if !hasLeafB && !hasLeaf1F {
			return false
		}

		var (
			vbEcx, vbEdx     uint32
			v1fEcx, v1fEdx   uint32
			abaStart, abaEnd uint32
		)

		// Triple-read ABA pattern to detect thread migration, bounded to 8
		// retries. Leaf 1's Initial APIC ID is the ABA guard.
		retries := 0
		for {
			_, l1EbxA, _, _ := cpuprobe.CPUIDSub(cpuprobe.LeafFeatures, 0)
			abaStart = (l1EbxA >> 24) & 0xFF

			if hasLeafB {
				_, _, vbEcx, vbEdx = cpuprobe.CPUIDSub(cpuprobe.LeafExtTopology, 0)
			}

			if hasLeaf1F {
				_, _, v1fEcx, v1fEdx = cpuprobe.CPUIDSub(cpuprobe.LeafV2ExtTopology, 0)
			}

			_, l1EbxB, _, _ := cpuprobe.CPUIDSub(cpuprobe.LeafFeatures, 0)
			abaEnd = (l1EbxB >> 24) & 0xFF

			retries++
			if abaStart == abaEnd || retries >= 8 {
				break
			}
		}

		// If we hit the retry limit and the thread is still migrating, abort
		// the check to prevent false positives.
		if abaStart != abaEnd {
			return false
		}

		initialAPICID := abaStart

		// Check Leaf 0x0B against Leaf 1.
		if hasLeafB {
			vbLevel := (vbEcx >> 8) & 0xFF
			if vbLevel != 0 {
				// If x2APIC ID is < 255, Initial APIC ID must match exactly.
				if vbEdx < 255 && (vbEdx&0xFF) != initialAPICID {
					return true
				}
			}
		}

		// Check Leaf 0x1F against Leaf 1, and cross-check with 0x0B.
		if hasLeaf1F {
			v1fLevel := (v1fEcx >> 8) & 0xFF
			if v1fLevel != 0 {
				if v1fEdx < 255 && (v1fEdx&0xFF) != initialAPICID {
					return true
				}

				// Cross-check 0x0B vs 0x1F if both are supported and valid.
				if hasLeafB {
					vbLevel := (vbEcx >> 8) & 0xFF
					if vbLevel != 0 && vbEdx != v1fEdx {
						return true
					}
				}
			}
		}
	} else if cpuprobe.IsAMD() {
		hasLeaf7 := cpuprobe.IsLeafSupported(cpuprobe.LeafExtFeatures)
		if !hasLeaf7 {
			return false
		}

		_, _, _, l7Edx := cpuprobe.CPUIDSub(cpuprobe.LeafExtFeatures, 0)

		// Intel enumerates hardware mitigations in Leaf 7.0.EDX:
		//   Bit 26: IBRS and IBPB
		//   Bit 27: STIBP
		//   Bit 31: SSBD
		// AMD processors strictly reserve these bits (force them to 0) and
		// instead enumerate their mitigations in Leaf 0x80000008.EBX.
		hasIntelIBRS := l7Edx&(1<<26) != 0
		hasIntelSTIBP := l7Edx&(1<<27) != 0
		hasIntelSSBD := l7Edx&(1<<31) != 0

		if hasIntelIBRS || hasIntelSTIBP || hasIntelSSBD {
			return true
		}
	}

	return false
}

// intelKgtSignature mirrors VM::intel_kgt_signature
// (@implements VM::KGT_SIGNATURE, points=80).
func intelKgtSignature() bool {
	_, _, ecx, edx := cpuprobe.CPUID(cpuprobe.LeafHvPrivileges)

	const ecxSig = 0x4D4D5645 // "EVMM"
	const edxSig = 0x43544E49 // "INTC"

	if ecx == ecxSig && edx == edxSig {
		return Add(BrandIntelKGT)
	}

	return false
}

// timer mirrors VM::timer (@implements VM::TIMER, points=45).
//
// Upstream's whole implementation is gated behind
// `#if (VMAWARE_X86 && VMAWARE_WINDOWS)`; every other platform falls
// straight through to an unconditional `return false;` (vmaware.hpp line
// 7557 opens that guard, lines 8088-8089 close it with the fallback), so
// that's exactly what every non-Windows build of this port does too.
//
// On Windows/x86 itself, upstream OR's together two signals:
//   - a CPUID-vs-reference-instruction latency race, run on a
//     priority-boosted, processor-group-affinity-pinned thread against a
//     lock-free software counter thread (timer::engine / timer::scheduler),
//     comparing best-of-N sample latencies; and
//   - an exception-latency probe (timer::exception_handler) that sets
//     EFLAGS.TF via inline asm to force a genuine hardware #DB
//     (single-step) exception, then times how long the compiler's own
//     structured exception handling (__try/__except, GetExceptionCode(),
//     GetExceptionInformation()) takes to regain control -- the exact same
//     "set the trap flag and time the trap" technique this port's own
//     stubs_unsupported.go already documents (for SINGLE_STEP, TRAP, UD,
//     INTERRUPT_SHADOW, EIP_OVERFLOW) as not portable to Go without
//     re-implementing a machine-code injector, since Go has no structured
//     exception handling construct to receive a hardware trap at all.
//
// Both signals are OR'd into a single boolean with no way to correctly gate
// just the SEH half on its own, and even the CPUID-latency half depends on
// hard real-time guarantees (locked, page-fault-free sample buffers, a
// busy-spinning counter thread pinned to a specific logical CPU, boosted
// thread/process priority) that Go's preemptible, GC-managed goroutine
// scheduler cannot reliably provide. Fabricating a partial, unverifiable
// timing heuristic here (this port's own test environment has no Windows
// target to validate against) would risk being *less* faithful than an
// honest stub, so timer() always returns false -- identical to how upstream
// itself behaves on every one of its own non-Windows targets.
func timer() bool {
	return false
}
