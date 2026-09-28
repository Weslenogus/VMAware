//go:build (linux || wasip1) && !amd64 && !386

package vmaware

func init() {
	RegisterTechnique(SystemRegisters, 50, systemRegisters)
}

// systemRegisters mirrors vmaware.hpp system_registers()'s Linux branch on
// non-x86 architectures: the upstream asm is gated by "VMAWARE_X86" and
// simply isn't compiled otherwise, so "found" stays false.
func systemRegisters() bool {
	return false
}
