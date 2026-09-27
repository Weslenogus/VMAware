package vmaware

import (
	"strings"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

func init() {
	RegisterTechnique(VMID, 100, vmid)
	RegisterTechnique(CPUBrand, 95, cpuBrandTechnique)
	RegisterTechnique(HypervisorBit, 150, hypervisorBit)
	RegisterTechnique(HypervisorStr, 150, hypervisorStr)
	RegisterTechnique(BochsCPU, 100, bochsCPU)
}

// vmidTemplate mirrors VM::cpu::vmid_template.
func vmidTemplate(leaf uint32) bool {
	brand := cpuprobe.CPUManufacturer(leaf)
	if brand == "" {
		return false
	}

	if strings.HasPrefix(brand, "Microsoft Hv") {
		// A Hyper-V host (root partition) is not itself a guest VM, and a
		// QEMU/KVM guest running with Hyper-V enlightenments is already
		// attributed to QEMU_KVM_HYPERV by hyperX(). In neither case should
		// "Microsoft Hv" be taken to mean the guest is genuine Hyper-V.
		if hyperX() == HyperVHost {
			return false
		}
		return Add(BrandHyperV)
	}

	if strings.Contains(brand, "KVM") {
		return Add(BrandKVM)
	}

	vmidBrandTable := []struct {
		sig   string
		brand BrandEnum
	}{
		{"VMwareVMware", BrandVMWARE},
		{"VBoxVBoxVBox", BrandVBOX},
		{"TCGTCGTCGTCG", BrandQEMU},
		{"XenVMMXenVMM", BrandXen},
		{"Linux KVM Hv", BrandKVMHyperV},
		{" prl hyperv ", BrandParallels},
		{" lrpepyh  vr", BrandParallels},
		{"bhyve bhyve ", BrandBHYVE},
		{"BHyVE BHyVE ", BrandBHYVE},
		{"ACRNACRNACRN", BrandACRN},
		{" QNXQVMBSQG ", BrandQNX},
		{"___ NVMM ___", BrandNVMM},
		{"OpenBSDVMM58", BrandBSDVMM},
		{"HAXMHAXMHAXM", BrandIntelHAXM},
		{"UnisysSpar64", BrandUnisys},
		{"SRESRESRESRE", BrandLMHS},
		{"Jailhouse\x00\x00\x00", BrandJailhouse},
		{"EVMMEVMMEVMM", BrandIntelKGT},
		{"Barevisor!\x00\x00", BrandBarevisor},
		{"MiniVisor\x00\x00\x00", BrandMiniVisor},
		{"IntelTDX    ", BrandIntelTDX},
		{"LKVMLKVMLKVM", BrandLKVM},
		{"Neko Project", BrandNekoProject},
		{"NoirVisor ZT", BrandNoirVisor},
		{"Compaq FX!32", BrandCompaq},
		{"Insignia 586", BrandInsignia},
		{"ConnectixCPU", BrandConnectix},
	}

	// brand is already cut at the first NUL by CPUManufacturer, so an entry
	// whose signature embeds NULs (Jailhouse, Barevisor!, MiniVisor) can
	// only match up to its own first NUL — exactly like the C++ memcmp(...,
	// 12) does against the raw (non-NUL-terminated) 12-byte buffer.
	for _, entry := range vmidBrandTable {
		sig := entry.sig
		if idx := strings.IndexByte(sig, 0); idx >= 0 {
			sig = sig[:idx]
		}
		if brand == sig {
			return Add(entry.brand)
		}
	}

	if strings.Contains(brand, "QXNQSBMV") {
		return Add(BrandQNX)
	}
	if strings.Contains(brand, "Apple VZ") {
		return Add(BrandAppleVZ)
	}
	if strings.Contains(brand, "PpyH") {
		return Add(BrandHyperPlatform)
	}

	return false
}

// vmid mirrors VM::vmid (@implements VM::VMID).
func vmid() bool {
	return vmidTemplate(cpuprobe.LeafBasicInfo) ||
		vmidTemplate(cpuprobe.LeafHypervisor) ||
		vmidTemplate(cpuprobe.LeafHvEnlightenment)
}

// cpuBrandTechnique mirrors VM::cpu_brand (@implements VM::CPU_BRAND).
func cpuBrandTechnique() bool {
	brand := cpuprobe.GetBrand()
	if brand == "" || brand == "Unknown" {
		return false
	}

	if strings.HasPrefix(brand, "QEMU Virtual CPU version") {
		return Add(BrandQEMU)
	}

	checks := []struct {
		text  string
		brand BrandEnum
	}{
		{"qemu", BrandQEMU},
		{"kvm", BrandKVM},
		{"vbox", BrandVBOX},
		{"virtualbox", BrandVBOX},
		{"bhyve", BrandBHYVE},
		{"parallels", BrandParallels},
	}

	for _, c := range checks {
		if strings.Contains(brand, c.text) {
			return Add(c.brand)
		}
	}

	if strings.Contains(brand, "monitor") ||
		strings.Contains(brand, "hypervisor") ||
		strings.Contains(brand, "hvisor") {
		return true
	}

	return false
}

// hypervisorBit mirrors VM::hypervisor_bit (@implements VM::HYPERVISOR_BIT).
func hypervisorBit() bool {
	_, _, ecx, _ := cpuprobe.CPUID(cpuprobe.LeafFeatures)
	const hypervisorMask = uint32(1) << 31
	state := hyperX()

	if ecx&hypervisorMask != 0 {
		// If the hypervisor bit is enabled but we're in a root partition,
		// don't flag it.
		if state == HyperVHost {
			return false
		}
		return true
	}

	// If the hypervisor bit is disabled but VMAware detects Hyper-V signals,
	// we're in an impossible situation (patching).
	return state == HyperVHost
}

// hypervisorStr mirrors VM::hypervisor_str (@implements VM::HYPERVISOR_STR).
func hypervisorStr() bool {
	if hyperX() == HyperVHost {
		return false
	}

	eax, ebx, ecx, edx := cpuprobe.CPUID(cpuprobe.LeafHypervisor)
	buf := make([]byte, 16)
	regs := [4]uint32{eax, ebx, ecx, edx}
	for i, r := range regs {
		buf[i*4+0] = byte(r)
		buf[i*4+1] = byte(r >> 8)
		buf[i*4+2] = byte(r >> 16)
		buf[i*4+3] = byte(r >> 24)
	}

	// strlen(out + 4) >= 4: length of the NUL-terminated tail starting
	// right after the EAX register (the max-leaf value, not part of the
	// vendor string) must be at least 4.
	tail := buf[4:]
	if idx := indexByteOrLen(tail, 0); idx < 4 {
		return false
	}
	return true
}

func indexByteOrLen(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return len(b)
}

// bochsCPU mirrors VM::bochs_cpu (@implements VM::BOCHS_CPU).
func bochsCPU() bool {
	intel := cpuprobe.IsIntel()
	amd := cpuprobe.IsAMD()

	if !intel && !amd {
		return false
	}

	brand := cpuprobe.GetBrand()

	if intel {
		// Bochs hardcodes 8 trailing spaces with no CPU clock frequency.
		if brand == "              Intel(R) Pentium(R) 4 CPU        " ||
			brand == "Intel(R) Pentium(R) 4 CPU" {
			return Add(BrandBochs)
		}
		return false
	}

	// amd
	if brand == "AMD Athlon(tm) processor" || strings.Contains(brand, "AMD Athlon(tm) processor") {
		return Add(BrandBochs)
	}

	// Check for absence of the AMD easter egg ("IT'S HAMMER TIME").
	if !cpuprobe.IsLeafSupported(cpuprobe.LeafFeatures) {
		return false
	}

	// Don't false-flag Microsoft's x64-on-ARM emulator.
	if strings.Contains(brand, "Virtual CPU") || !strings.Contains(brand, "AMD") {
		return false
	}

	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafFeatures)

	isK8 := func(eax uint32) bool {
		baseFamily := (eax >> 8) & 0xF
		extendedFamily := (eax >> 20) & 0xFF
		return baseFamily == 0xF && extendedFamily == 0
	}

	if !isK8(eax) {
		return false
	}

	_, _, ecxBochs, _ := cpuprobe.CPUID(cpuprobe.LeafAMDEasterEgg)

	// Real K8 returns 0x2052454D on ECX ("MER "). Bochs returns 0.
	if ecxBochs == 0 {
		return Add(BrandBochs)
	}

	return false
}
