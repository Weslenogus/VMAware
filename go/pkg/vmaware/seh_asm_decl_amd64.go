//go:build windows && amd64

package vmaware

// Declarations for the amd64-only leaf functions implemented in
// seh_asm_amd64.s (AES-NI/AVX/AVX2 probes used by cpu_heuristic()).

func aesEncProbe(blockPtr, keyPtr, outPtr *byte)
func xgetbv0() (lo, hi uint32)
func avxAddProbe(aPtr, bPtr, outPtr *byte)
func avx2AddProbe(aPtr, bPtr, outPtr *byte)
