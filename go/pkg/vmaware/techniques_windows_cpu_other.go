//go:build windows && !amd64

package vmaware

// The AES-NI/AVX/AVX2 probes are only assembled for amd64 (see
// seh_asm_amd64.s); on every other architecture cpu_heuristic()'s first
// stage is skipped, matching a conservative "can't safely probe, don't
// false-flag" fallback.
func cpuHeuristicAESAVX() bool { return false }
