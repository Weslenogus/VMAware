//go:build windows && (amd64 || 386)

package vmaware

// Declarations for the shared (amd64 and 386) leaf functions implemented in
// seh_asm_amd64.s / seh_asm_386.s. See those files' header comments and
// seh_windows.go for the fault-recovery mechanism they're designed around.

func callRaw(addr uintptr)
func rdmsrProbe(msr uint32)
func wrmsrProbe(msr, lo, hi uint32)
func clzeroProbe(ptr uintptr)
func sgdtProbe(out *byte)
func sidtProbe(out *byte)
