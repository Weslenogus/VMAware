//go:build windows && 386

package vmaware

import "unsafe"

// Byte offsets into the OS-supplied x86 CONTEXT structure (winnt.h), stable
// ABI since Windows NT. We never allocate a CONTEXT ourselves on this path
// (see EXCEPTION_POINTERS.ContextRecord in seh_windows.go).
const (
	ctxOffsetEsp = 196 // CONTEXT.Esp
	ctxOffsetEip = 184 // CONTEXT.Eip
	ctxOffsetEbx = 164 // CONTEXT.Ebx
)

// popReturnAndContinue emulates a plain RET at the fault site (see the
// amd64 version's comment for the rationale).
func popReturnAndContinue(ctxPtr unsafe.Pointer) {
	espField := (*uint32)(unsafe.Add(ctxPtr, ctxOffsetEsp))
	esp := *espField
	if esp == 0 {
		return
	}
	retAddr := *(*uint32)(unsafe.Pointer(uintptr(esp)))
	*(*uint32)(unsafe.Add(ctxPtr, ctxOffsetEip)) = retAddr
	*espField = esp + 4
}

// fixupVPCContext mirrors the is_inside_vpc SEH filter from vpc_invalid():
// on an illegal-instruction fault whose address matches the 4-byte VPC
// backdoor opcode (0F 3F 07 0B), force EBX to 0xFFFFFFFF (the "not inside
// Virtual PC" sentinel the probe tests for) and skip past the 4 faulting
// bytes, exactly like the upstream filter's ContextRecord->Eip += 4.
func fixupVPCContext(ctxPtr unsafe.Pointer, faultAddr uintptr) bool {
	if faultAddr == 0 {
		return false
	}
	opcode := *(*[4]byte)(unsafe.Pointer(faultAddr))
	if opcode[0] != 0x0F || opcode[1] != 0x3F || opcode[2] != 0x07 || opcode[3] != 0x0B {
		return false
	}

	eipField := (*uint32)(unsafe.Add(ctxPtr, ctxOffsetEip))
	eip := *eipField
	if uint32(faultAddr) != eip {
		return false
	}

	*(*uint32)(unsafe.Add(ctxPtr, ctxOffsetEbx)) = 0xFFFFFFFF
	*eipField = eip + 4
	return true
}
