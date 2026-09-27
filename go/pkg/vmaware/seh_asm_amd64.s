#include "textflag.h"

// This file holds every "deliberately risky, single hardware instruction"
// leaf used under seh_windows.go's guardedAbortCall/guardedVPCInvalid: each
// is NOSPLIT with a $0 frame and pushes nothing onto the stack before its
// risky instruction, which is exactly what the fault-recovery trick in
// seh_windows.go depends on (see its comment). None of these allocate or
// execute freshly-generated machine code; each is a single, statically
// compiled instruction, the same category as cpuprobe's CPUID leaf (a
// hardware instruction the Go toolchain assembles directly into the
// binary), never machine code written to memory at runtime.

// func callRaw(addr uintptr)
// Calls an arbitrary, already-mapped code address with no arguments and
// discards any return value. Used by hypervisor_hook() to re-execute a
// single byte inside ntdll (or a synthetic boundary-straddling stub) and
// let guardedAbortCall report whether doing so still faults.
TEXT ·callRaw(SB), NOSPLIT, $0-8
	MOVQ addr+0(FP), AX
	CALL AX
	RET

// func rdmsrProbe(msr uint32)
// msr() : plain RDMSR, a ring-0-only instruction that must #GP in user mode
// on real hardware.
TEXT ·rdmsrProbe(SB), NOSPLIT, $0-4
	MOVL msr+0(FP), CX
	RDMSR
	RET

// func wrmsrProbe(msr, lo, hi uint32)
// msr() : plain WRMSR, same rationale as rdmsrProbe.
TEXT ·wrmsrProbe(SB), NOSPLIT, $0-12
	MOVL msr+0(FP), CX
	MOVL lo+4(FP), AX
	MOVL hi+8(FP), DX
	WRMSR
	RET

// func clzeroProbe(ptr uintptr)
// cpu_heuristic() : CLZERO (AMD-only) zeroes a 64-byte cache line at ptr,
// then MFENCE orders the write. On a CPU that doesn't implement it, this
// is an illegal instruction (#UD); on one that does (real or faithfully
// emulated AMD), ptr's cache line reads back as all zero afterwards.
TEXT ·clzeroProbe(SB), NOSPLIT, $0-8
	MOVQ ptr+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0xFC // CLZERO
	BYTE $0x0F; BYTE $0xAE; BYTE $0xF0 // MFENCE
	RET

// func sgdtProbe(out *byte) // out must have room for 10 bytes
// system_registers() technique 1: SGDT stores the current GDTR (2-byte
// limit + 8-byte base on amd64) into memory. Some CPUs with UMIP enabled
// raise #GP for this in ring 3, which is exactly what guardedAbortCall is
// for.
TEXT ·sgdtProbe(SB), NOSPLIT, $0-8
	MOVQ out+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0x00 // SGDT [RAX]
	RET

// func sidtProbe(out *byte) // out must have room for 10 bytes
// system_registers() technique 3: SIDT, same shape as SGDT above but for
// the IDTR.
TEXT ·sidtProbe(SB), NOSPLIT, $0-8
	MOVQ out+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0x08 // SIDT [RAX]
	RET

// func aesEncProbe(blockPtr, keyPtr, outPtr *byte)
// cpu_heuristic() AES-NI probe: out = AESENC(block XOR key, key), the exact
// sequence upstream's aes_executor runs, so a hypervisor that reports
// AES-NI in CPUID but doesn't actually support it faults here, and one
// that hides a genuinely present AES-NI unit produces a wrong (but
// non-faulting) result the Go side compares against a reference computed
// in software.
TEXT ·aesEncProbe(SB), NOSPLIT, $0-24
	MOVQ blockPtr+0(FP), AX
	MOVQ keyPtr+8(FP), BX
	MOVQ outPtr+16(FP), CX
	MOVOU (AX), X0
	MOVOU (BX), X1
	PXOR  X1, X0
	AESENC X1, X0
	MOVOU X0, (CX)
	RET

// func xgetbv0() (lo, hi uint32)
// cpu_heuristic() AVX/AVX2 probes: reads XCR0 (extended control register 0)
// to confirm the OS has enabled the relevant state before actually issuing
// an AVX/AVX2 instruction, exactly like upstream's _xgetbv(0) call.
TEXT ·xgetbv0(SB), NOSPLIT, $0-8
	MOVL $0, CX
	XGETBV
	MOVL AX, lo+0(FP)
	MOVL DX, hi+4(FP)
	RET

// func avxAddProbe(aPtr, bPtr, outPtr *byte) // 8 float32 (32 bytes) each
// cpu_heuristic() AVX probe: out = a + b as 8 packed singles via a 256-bit
// VADDPS, the same shape as upstream's avx_executor.
TEXT ·avxAddProbe(SB), NOSPLIT, $0-24
	MOVQ aPtr+0(FP), AX
	MOVQ bPtr+8(FP), BX
	MOVQ outPtr+16(FP), CX
	VMOVUPS (AX), Y0
	VMOVUPS (BX), Y1
	VADDPS  Y1, Y0, Y2
	VMOVUPS Y2, (CX)
	VZEROUPPER
	RET

// func avx2AddProbe(aPtr, bPtr, outPtr *byte) // 8 uint32 (32 bytes) each
// cpu_heuristic() AVX2 probe: out = a + b as 8 packed dwords via a 256-bit
// VPADDD, the same shape as upstream's avx2_executor.
TEXT ·avx2AddProbe(SB), NOSPLIT, $0-24
	MOVQ aPtr+0(FP), AX
	MOVQ bPtr+8(FP), BX
	MOVQ outPtr+16(FP), CX
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1
	VPADDD  Y1, Y0, Y2
	VMOVDQU Y2, (CX)
	VZEROUPPER
	RET
