//go:build !windows

package vmaware

// hyperX mirrors VM::util::hyper_x() for non-Windows targets: the upstream
// #if !VMAWARE_WINDOWS branch always returns HYPERV_UNKNOWN, since the real
// implementation depends on Windows-only APIs (NtQuerySystemInformation,
// tbs.dll). See hyperx_windows.go for the real implementation.
func hyperX() HyperXState {
	return HyperVUnknown
}
