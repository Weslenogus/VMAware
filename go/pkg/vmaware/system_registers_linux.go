//go:build linux && (amd64 || 386)

package vmaware

import (
	"unsafe"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

func init() {
	RegisterTechnique(SystemRegisters, 50, systemRegisters)
}

// rawSIDT executes the x86 SIDT instruction (Store Interrupt Descriptor
// Table Register), writing the resulting pseudo-descriptor (a 2-byte limit
// followed by a 4-or-8-byte base, depending on GOARCH) starting at *buf.
// Implemented in sidt_amd64.s / sidt_386.s: a single hardware instruction
// compiled directly into the binary -- the same technique cpuprobe's
// rawCPUID uses for CPUID, not code injection of any kind. buf must point
// to a buffer of at least 16 bytes.
func rawSIDT(buf *byte)

// systemRegisters mirrors vmaware.hpp system_registers()'s Linux
// (VMAWARE_LINUX && (VMAWARE_GCC || VMAWARE_CLANG) && VMAWARE_X86) branch --
// the classic "Red Pill" SIDT check (@implements VM::SYSTEM_REGISTERS).
//
// Upstream wraps the inline "sidt %0" asm in a SIGSEGV/SIGILL
// sigsetjmp/siglongjmp guard, because on some restrictive sandboxes
// executing SIDT can trap. Go has no equivalent of sigsetjmp/longjmp
// without cgo, so that guard is not replicated here. This is safe on every
// real CPU and every mainstream hypervisor (KVM, VMware, VirtualBox,
// Hyper-V): SIDT is unprivileged in ring 3 and never faults there, which is
// the entire premise of the technique below (it reads whatever IDT base
// the hypervisor set up, rather than trapping).
func systemRegisters() bool {
	// util::is_x86_process_on_arm()'s generic (non-Windows) fallback: true
	// when the hypervisor-leaf vendor string reports "VirtualApple" (Apple
	// Rosetta) or "PowerVM Lx86" (IBM PowerVM's x86 emulation layer).
	if cpuprobe.IsLeafSupported(cpuprobe.LeafHypervisor) {
		vendor := cpuprobe.CPUManufacturer(cpuprobe.LeafHypervisor)
		if vendor == "VirtualApple" || vendor == "PowerVM Lx86" {
			return false
		}
	}

	var buf [16]byte
	rawSIDT(&buf[0])

	if unsafe.Sizeof(uintptr(0)) == 8 {
		// 64-bit Linux: IDT descriptor is 10 bytes (2-byte limit + 8-byte
		// base); the 10th byte is checked.
		return buf[9] == 0x00
	}
	// 32-bit Linux: IDT descriptor is 6 bytes (2-byte limit + 4-byte base);
	// the 6th byte is checked.
	return buf[5] == 0x00
}
