//go:build windows

package vmaware

// This file intentionally implements nothing.
//
// Nine Windows-only techniques in vmaware.hpp work by writing raw x86
// machine code (hand-assembled byte arrays such as cpuid_singlestep_stub,
// dbvm_intel_stub/dbvm_amd_stub/dbvm_icebp_stub, trampoline_stub,
// switch_stub, vmload_stub, ud_stub, limit_15_stub, int3_stub,
// alu_flags_stub, x87_precision_stub, fpu_overflow_stub and
// aam_radix_stub) into an executable page and running it, in order to:
//   - single-step or hardware-breakpoint the CPU across a CPUID/RDPRU and
//     watch for a hypervisor mis-emulating the trap (Trap, SingleStep,
//     InterruptShadow),
//   - probe a hypervisor directly with vmcall/vmmcall/icebp (DBVM,
//     KVMInterception, SVMExceptions),
//   - deliberately fault the CPU (#UD, a 16-byte-boundary instruction, an
//     IRET stack switch, a software INT3, an x87/FPU corner case, an
//     undocumented AAM radix) and inspect exactly how the fault unwinds
//     (UD, EIPOverflow, Emulation).
//
// Porting that faithfully means re-implementing a small machine-code
// assembler/injector, which is a fundamentally different (and far riskier)
// piece of software than the rest of this library — and it is moot for the
// WASM target either way, since WebAssembly has no CPUID/vmcall/hardware
// breakpoint/IRET instructions and no ability to execute injected native
// code at all. Rather than guess at a reimplementation that can't be
// verified against the original byte-for-byte, each of these always
// returns false, in the same "unsupported" spirit as isUnsupportedForPlatform.
// Points reflect the upstream technique_table entry for documentation
// purposes only, since a technique that never returns true never
// contributes them.
func init() {
	RegisterTechnique(Trap, 150, func() bool { return false })
	RegisterTechnique(UD, 100, func() bool { return false })
	RegisterTechnique(InterruptShadow, 150, func() bool { return false })
	RegisterTechnique(DBVM, 150, func() bool { return false })
	RegisterTechnique(SingleStep, 150, func() bool { return false })
	RegisterTechnique(EIPOverflow, 150, func() bool { return false })
	RegisterTechnique(SVMExceptions, 35, func() bool { return false })
	RegisterTechnique(KVMInterception, 150, func() bool { return false })
	RegisterTechnique(Emulation, 100, func() bool { return false })
}
