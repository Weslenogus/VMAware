//go:build windows

package vmaware

// Shared "structured exception handling" substitute used by several
// techniques that upstream wraps in MSVC/GCC __try/__except (or a manually
// installed RtlAddVectoredExceptionHandler) around a single deliberately
// risky instruction: RDMSR/WRMSR (msr()), SGDT/SIDT/SMSW (systemRegisters()),
// the VPC backdoor instruction (vpcInvalid()), AES-NI/AVX/AVX2/AVX512/CLZERO
// probes (cpuHeuristic()), and re-executing a patched ntdll byte
// (hypervisorHook()).
//
// Go has no __try/__except. What it does have is AddVectoredExceptionHandler
// (a documented, ordinary Windows API, resolved here exactly like every
// other native call in this port) plus windows.NewCallback, which lets the
// OS call back into a real Go function with the live EXCEPTION_POINTERS on
// any hardware exception raised on any thread. Every risky instruction this
// file guards is executed by a small, argument-only, NOSPLIT Go assembly
// leaf function (see seh_windows_amd64.s / seh_windows_386.s) that pushes
// nothing onto the stack before the risky instruction, so at the moment it
// faults, the top of the stack is always the return address into that leaf's
// caller. Our vectored handler exploits exactly that: on a fault while
// "armed", it pops that address into the instruction pointer and advances
// the stack pointer past it, which is byte-for-byte what a plain RET would
// have done, then resumes execution there via EXCEPTION_CONTINUE_EXECUTION.
// The effect is identical to the C++ side's "catch the exception and return
// false/true from the wrapping lambda": the call site sees the leaf function
// return (with whatever registers it left, which none of the call sites
// here read), and vehFaulted records that a fault happened.
//
// vpcInvalid() needs different handling (fix up EBX/EIP and truly resume
// mid-instruction, not abort), so it gets its own vectored mode.
//
// Every guarded call goes through vehMu, so at most one probe is "armed" at
// a time process-wide, matching the de facto single-threaded assumption the
// upstream lambdas make.

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	exceptionContinueExecution = ^uintptr(0) // -1 as LONG
	exceptionContinueSearch    = uintptr(0)
)

const (
	excCodeIllegalInstruction = 0xC000001D
)

// exceptionRecordT mirrors EXCEPTION_RECORD closely enough for our purposes
// (we only ever read ExceptionCode and ExceptionAddress). Using uintptr for
// pointer-sized fields lets a single definition match the real struct's
// layout on both 386 and amd64, since Go's struct layout rules insert the
// same alignment padding the C compiler would.
type exceptionRecordT struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

// exceptionPointersT mirrors EXCEPTION_POINTERS.
type exceptionPointersT struct {
	ExceptionRecord *exceptionRecordT
	ContextRecord   unsafe.Pointer // opaque CONTEXT*; read/written by raw offset only
}

const (
	vehModeNone     = 0
	vehModeAbort    = 1 // pop return address into IP/SP and continue (generic "did it fault" probe)
	vehModeVPCFixup = 2 // vpc_invalid(): on #UD at the expected 4-byte opcode, set EBX=0xFFFFFFFF and skip 4 bytes (386 only)
)

var (
	vehMu       sync.Mutex
	vehInitOnce sync.Once
	vehHandle   uintptr

	// Guarded, single-probe-at-a-time state. Only touched while vehMu is held.
	vehMode        int
	vehFaulted     bool
	vehExpectedLen uintptr // vehModeVPCFixup: bytes to skip on match
)

var (
	procAddVectoredExceptionHandler    = procOrNil(modKernel32, "AddVectoredExceptionHandler")
	procRemoveVectoredExceptionHandler = procOrNil(modKernel32, "RemoveVectoredExceptionHandler")
)

func vehCallback(exceptionInfo uintptr) uintptr {
	if vehMode == vehModeNone {
		return exceptionContinueSearch
	}
	ep := (*exceptionPointersT)(unsafe.Pointer(exceptionInfo))
	if ep == nil || ep.ExceptionRecord == nil || ep.ContextRecord == nil {
		return exceptionContinueSearch
	}

	switch vehMode {
	case vehModeAbort:
		vehFaulted = true
		popReturnAndContinue(ep.ContextRecord)
		return exceptionContinueExecution

	case vehModeVPCFixup:
		if ep.ExceptionRecord.ExceptionCode != excCodeIllegalInstruction {
			return exceptionContinueSearch
		}
		if !fixupVPCContext(ep.ContextRecord, ep.ExceptionRecord.ExceptionAddress) {
			return exceptionContinueSearch
		}
		vehFaulted = true
		return exceptionContinueExecution
	}

	return exceptionContinueSearch
}

func ensureVEHInstalled() bool {
	vehInitOnce.Do(func() {
		if procAddVectoredExceptionHandler == nil {
			return
		}
		cb := windows.NewCallback(vehCallback)
		r1, _, _ := procAddVectoredExceptionHandler.Call(1 /* CALL_FIRST */, cb)
		vehHandle = r1
	})
	return vehHandle != 0
}

// guardedAbortCall arms the abort-on-any-exception mode, runs fn (expected to
// call exactly one of the risky asm leaf functions below), and reports
// whether a hardware exception occurred during it.
func guardedAbortCall(fn func()) (faulted bool) {
	vehMu.Lock()
	defer vehMu.Unlock()

	if !ensureVEHInstalled() {
		// No VEH available: refuse to run instructions that upstream only
		// ever executes under exception protection, rather than risk an
		// unhandled fault crashing the process.
		return false
	}

	vehMode = vehModeAbort
	vehFaulted = false

	fn()

	faulted = vehFaulted
	vehMode = vehModeNone
	return faulted
}

// guardedVPCInvalid arms the vpc_invalid()-specific fixup mode and runs fn
// (the VPC backdoor probe). It returns whether the #UD handler fired (i.e.
// the instruction was NOT silently handled by a Virtual PC host).
func guardedVPCInvalid(fn func()) (trapped bool) {
	vehMu.Lock()
	defer vehMu.Unlock()

	if !ensureVEHInstalled() {
		return false
	}

	vehMode = vehModeVPCFixup
	vehFaulted = false

	fn()

	trapped = vehFaulted
	vehMode = vehModeNone
	return trapped
}
