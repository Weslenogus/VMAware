// Package cpuprobe is a small, self-contained CPUID wrapper mirroring
// VM::cpu from vmaware.hpp: it exists so the technique ports need exact,
// byte-for-byte leaf values (brand strings, hypervisor vendor IDs, raw
// feature bits) rather than a library's own parsing/trimming of them.
package cpuprobe

// Leaf mirrors VM::cpu::leaf's CPUID leaf constants.
const (
	LeafBasicInfo       uint32 = 0x00000000
	LeafFeatures        uint32 = 0x00000001
	LeafExtFeatures     uint32 = 0x00000007
	LeafExtTopology     uint32 = 0x0000000B
	LeafV2ExtTopology   uint32 = 0x0000001F
	LeafHypervisor      uint32 = 0x40000000
	LeafHvInterface     uint32 = 0x40000001
	LeafHvPrivileges    uint32 = 0x40000003
	LeafHvProcessors    uint32 = 0x40000005
	LeafHvNested        uint32 = 0x40000006
	LeafHvEnlightenment uint32 = 0x40000100
	LeafFuncExt         uint32 = 0x80000000
	LeafProcExt         uint32 = 0x80000001
	LeafBrand1          uint32 = 0x80000002
	LeafBrand2          uint32 = 0x80000003
	LeafBrand3          uint32 = 0x80000004
	LeafExtLimits       uint32 = 0x80000008
	LeafEncryptedMem    uint32 = 0x8000001F
	LeafAMDEasterEgg    uint32 = 0x8fffffff
)
