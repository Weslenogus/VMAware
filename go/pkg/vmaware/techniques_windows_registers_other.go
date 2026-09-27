//go:build windows && !386

package vmaware

// SLDT and SMSW are VMAWARE_X86_32-only techniques upstream; on every other
// architecture (amd64 included) they always return false.

func systemRegistersSLDT() bool { return false }
func systemRegistersSMSW() bool { return false }
