//go:build windows && amd64

package vmaware

// vpc_invalid() and vmware_str() are both VMAWARE_X86_32-only upstream (the
// VPC backdoor opcode and the STR-based check are 32-bit-specific
// techniques); on amd64 they always fall through to "return false".

func vpcInvalidTechnique() bool { return false }
func vmwareStrTechnique() bool  { return false }
