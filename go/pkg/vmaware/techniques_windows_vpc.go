//go:build windows

package vmaware

// Port of vpc_invalid() (@implements VM::VPC_INVALID, vmaware.hpp
// ~12074-12146) and vmware_str() (@implements VM::VMWARE_STR, vmaware.hpp
// ~12147-12179). Both are VMAWARE_X86_32-only techniques (upstream guards
// them with #if VMAWARE_X86_32); on amd64 they always return false, exactly
// like the C++ side falls through its #if/#else to "return false" on any
// non-32-bit build.

func init() {
	RegisterTechnique(VPCInvalid, 75, vpcInvalidTechnique)
	RegisterTechnique(VMwareStr, 35, vmwareStrTechnique)
}
