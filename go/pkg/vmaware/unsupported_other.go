//go:build !linux && !windows && !darwin

package vmaware

// On an OS this port doesn't target (including js/wasm and wasip1), the
// upstream C++ #else branch evaluates to "false" (nothing is marked
// unsupported by the platform-range check) — the empty technique table
// entries end up being skipped elsewhere in RunAll/Check anyway.
func isUnsupportedForPlatform(_ EnumFlag) bool {
	return false
}
