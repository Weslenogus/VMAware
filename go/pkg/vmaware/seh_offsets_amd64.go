//go:build windows && amd64

package vmaware

import "unsafe"

// Byte offsets into the OS-supplied AMD64 CONTEXT structure (winnt.h),
// stable ABI since Windows Vista x64. We never allocate a CONTEXT
// ourselves on this path (see EXCEPTION_POINTERS.ContextRecord in
// seh_windows.go), so only the two fields the abort trick needs are named.
const (
	ctxOffsetRsp = 152 // CONTEXT.Rsp
	ctxOffsetRip = 248 // CONTEXT.Rip
)

// popReturnAndContinue emulates a plain RET at the fault site: it reads the
// return address sitting at [Rsp] and installs it as Rip, then advances Rsp
// past it, exactly what the CPU would have done for a RET instruction.
func popReturnAndContinue(ctxPtr unsafe.Pointer) {
	rspField := (*uint64)(unsafe.Add(ctxPtr, ctxOffsetRsp))
	rsp := *rspField
	if rsp == 0 {
		return
	}
	retAddr := *(*uint64)(unsafe.Pointer(uintptr(rsp)))
	*(*uint64)(unsafe.Add(ctxPtr, ctxOffsetRip)) = retAddr
	*rspField = rsp + 8
}

// fixupVPCContext is unused on amd64: vpc_invalid() is a VMAWARE_X86_32-only
// technique (it depends on a 32-bit-only undocumented backdoor opcode), so
// vehModeVPCFixup is never armed here. Kept only so seh_windows.go's mode
// switch compiles on every architecture.
func fixupVPCContext(ctxPtr unsafe.Pointer, faultAddr uintptr) bool {
	return false
}
