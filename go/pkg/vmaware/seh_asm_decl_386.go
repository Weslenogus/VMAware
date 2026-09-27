//go:build windows && 386

package vmaware

// Declarations for the 386-only leaf functions implemented in
// seh_asm_386.s (SMSW/SLDT for system_registers(), and the Virtual PC
// backdoor probe for vpc_invalid()).

func smswProbe() uint32
func sldtProbe(out *byte)
func vpcInvalidProbe() uint32
