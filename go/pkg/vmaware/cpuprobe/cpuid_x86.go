//go:build amd64 || 386

package cpuprobe

// rawCPUID executes a single CPUID instruction (leaf in eaxIn, subleaf in
// ecxIn) and returns the four result registers. Implemented in
// cpuid_amd64.s / cpuid_386.s: a single hardware instruction compiled
// directly into the binary, the exact equivalent of the C++ side's
// __cpuid_count/__cpuidex intrinsic — not code injection of any kind.
func rawCPUID(eaxIn, ecxIn uint32) (eax, ebx, ecx, edx uint32)
