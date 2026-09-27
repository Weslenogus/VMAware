//go:build !amd64 && !386

package cpuprobe

// rawCPUID is a no-op on non-x86 architectures, mirroring the C++ side's
// "#if !VMAWARE_X86 ... VMAWARE_UNUSED(...)" branches: every leaf reads as
// all-zero, which naturally makes every dependent check (is_leaf_supported,
// hypervisor_bit, brand string, ...) fall through to its "not found" result.
func rawCPUID(eaxIn, ecxIn uint32) (eax, ebx, ecx, edx uint32) {
	return 0, 0, 0, 0
}
