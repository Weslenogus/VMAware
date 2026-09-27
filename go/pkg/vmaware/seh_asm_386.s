#include "textflag.h"

// See seh_asm_amd64.s's header comment: every leaf here is NOSPLIT, has a
// $0 frame, and pushes nothing before its risky instruction, which
// seh_windows.go's fault-recovery trick depends on. vpcInvalidProbe is the
// one exception that pushes registers, which is why it's paired with
// guardedVPCInvalid (context fixup + mid-instruction resume) rather than
// guardedAbortCall.

// func callRaw(addr uintptr)
TEXT ·callRaw(SB), NOSPLIT, $0-4
	MOVL addr+0(FP), AX
	CALL AX
	RET

// func rdmsrProbe(msr uint32)
TEXT ·rdmsrProbe(SB), NOSPLIT, $0-4
	MOVL msr+0(FP), CX
	RDMSR
	RET

// func wrmsrProbe(msr, lo, hi uint32)
TEXT ·wrmsrProbe(SB), NOSPLIT, $0-12
	MOVL msr+0(FP), CX
	MOVL lo+4(FP), AX
	MOVL hi+8(FP), DX
	WRMSR
	RET

// func clzeroProbe(ptr uintptr)
TEXT ·clzeroProbe(SB), NOSPLIT, $0-4
	MOVL ptr+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0xFC // CLZERO
	BYTE $0x0F; BYTE $0xAE; BYTE $0xF0 // MFENCE
	RET

// func sgdtProbe(out *byte) // out must have room for 6 bytes
TEXT ·sgdtProbe(SB), NOSPLIT, $0-4
	MOVL out+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0x00 // SGDT [EAX]
	RET

// func sidtProbe(out *byte) // out must have room for 6 bytes
TEXT ·sidtProbe(SB), NOSPLIT, $0-4
	MOVL out+0(FP), AX
	BYTE $0x0F; BYTE $0x01; BYTE $0x08 // SIDT [EAX]
	RET

// func smswProbe() uint32
// system_registers() technique 4: prime EAX with a 0xCCCCCCCC sentinel and
// issue SMSW EAX, which (per the Offensive Computing "red pill" technique)
// only ever updates the low 16 bits of a 32-bit destination register on
// real hardware, leaving the sentinel's high 16 bits intact.
TEXT ·smswProbe(SB), NOSPLIT, $0-4
	MOVL $0xCCCCCCCC, AX
	BYTE $0x0F; BYTE $0x01; BYTE $0xE0 // SMSW EAX
	MOVL AX, ret+0(FP)
	RET

// func sldtProbe(out *byte)
// system_registers() technique 2: SLDT stores the current LDTR selector
// (16 bits) into out[0:2]; the caller pre-seeds out[0:4] with a marker
// pattern to detect whether anything was actually written.
TEXT ·sldtProbe(SB), NOSPLIT, $0-4
	MOVL out+0(FP), AX
	BYTE $0x0F; BYTE $0x00; BYTE $0x00 // SLDT [EAX]
	RET

// func vpcInvalidProbe() uint32
// vpc_invalid(): the undocumented Connectix/Microsoft Virtual PC "backdoor"
// opcode. Inside a genuine Virtual PC host this executes as a no-op and
// (per the well known VM-detection technique this mirrors) leaves EBX
// cleared; anywhere else it's an undefined instruction (#UD), which
// seh_offsets_386.go's fixupVPCContext catches, forces EBX to 0xFFFFFFFF,
// and resumes 4 bytes past — exactly mirroring the upstream SEH filter.
TEXT ·vpcInvalidProbe(SB), NOSPLIT, $0-4
	MOVL $0, BX
	MOVL $1, AX
	BYTE $0x0F; BYTE $0x3F; BYTE $0x07; BYTE $0x0B // VPCEXT backdoor
	XORL CX, CX
	TESTL BX, BX
	JNZ  vpcinvalid_done
	MOVL $1, CX
vpcinvalid_done:
	MOVL CX, ret+0(FP)
	RET

// func strProbe() uint16
// vmware_str(): STR (store task register) is not privileged and always
// succeeds in ring 3, so this needs no fault guard.
TEXT ·strProbe(SB), NOSPLIT, $0-2
	BYTE $0x0F; BYTE $0x00; BYTE $0xC8 // STR AX (ModRM 11 001 000 = /1, AX)
	MOVW AX, ret+0(FP)
	RET
