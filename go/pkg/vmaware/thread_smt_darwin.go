//go:build darwin

package vmaware

import "golang.org/x/sys/unix"

// isSMTActive mirrors the VMAWARE_APPLE branch of thread_mismatch()'s
// is_smt_active lambda (vmaware.hpp lines ~7126-7136): compare
// hw.logicalcpu against hw.physicalcpu via sysctlbyname.
func isSMTActive() bool {
	logical, err := unix.SysctlUint32("hw.logicalcpu")
	if err != nil {
		return false
	}

	physical, err := unix.SysctlUint32("hw.physicalcpu")
	if err != nil {
		return false
	}

	return logical > physical
}
