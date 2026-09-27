package vmaware

import "sort"

// brandNames mirrors the VM::brands string table.
var brandNames = [BrandNullBrand + 1]string{
	BrandVBOX:              "VirtualBox",
	BrandVMWARE:            "VMware",
	BrandVMWAREExpress:     "VMware Express",
	BrandVMWAREESX:         "VMware ESX",
	BrandVMWAREGSX:         "VMware GSX",
	BrandVMWAREWorkstation: "VMware Workstation",
	BrandVMWAREFusion:      "VMware Fusion",
	BrandVMWAREHard:        "VMware (with VmwareHardenedLoader)",
	BrandBHYVE:             "bhyve",
	BrandKVM:               "KVM",
	BrandQEMU:              "QEMU",
	BrandQEMUKVM:           "QEMU+KVM",
	BrandKVMHyperV:         "KVM Hyper-V Enlightenment",
	BrandQEMUKVMHyperV:     "QEMU+KVM Hyper-V Enlightenment",
	BrandHyperV:            "Microsoft Hyper-V",
	BrandHyperVVPC:         "Microsoft Virtual PC/Hyper-V",
	BrandParallels:         "Parallels",
	BrandXen:               "Xen HVM",
	BrandACRN:              "ACRN",
	BrandQNX:               "QNX hypervisor",
	BrandHybrid:            "Hybrid Analysis",
	BrandSandboxie:         "Sandboxie",
	BrandDocker:            "Docker",
	BrandWine:              "Wine",
	BrandVPC:               "Virtual PC",
	BrandAnubis:            "Anubis",
	BrandJoebox:            "JoeBox",
	BrandThreatExpert:      "ThreatExpert",
	BrandCWSandbox:         "CWSandbox",
	BrandComodo:            "Comodo",
	BrandBochs:             "Bochs",
	BrandNVMM:              "NetBSD NVMM",
	BrandBSDVMM:            "OpenBSD VMM",
	BrandIntelHAXM:         "Intel HAXM",
	BrandUnisys:            "Unisys s-Par",
	BrandLMHS:              "Lockheed Martin LMHS",
	BrandCuckoo:            "Cuckoo",
	BrandBluestacks:        "BlueStacks",
	BrandJailhouse:         "Jailhouse",
	BrandAppleVZ:           "Apple VZ",
	BrandIntelKGT:          "Intel KGT (Trusty)",
	BrandAzureHyperV:       "Microsoft Azure Hyper-V",
	BrandSimpleVisor:       "SimpleVisor",
	BrandHyperVRoot:        "Hyper-V root partition (host system)",
	BrandUML:               "User-mode Linux",
	BrandPowerVM:           "IBM PowerVM",
	BrandGCE:               "Google Compute Engine (KVM)",
	BrandOpenStack:         "OpenStack (KVM)",
	BrandKubeVirt:          "KubeVirt (KVM)",
	BrandAWSNitro:          "AWS Nitro System EC2 (KVM-based)",
	BrandPodman:            "Podman",
	BrandWSL:               "WSL",
	BrandOpenVZ:            "OpenVZ",
	BrandBarevisor:         "Barevisor",
	BrandHyperPlatform:     "HyperPlatform",
	BrandMiniVisor:         "MiniVisor",
	BrandIntelTDX:          "Intel TDX",
	BrandLKVM:              "LKVM",
	BrandAMDSev:            "AMD SEV",
	BrandAMDSevES:          "AMD SEV-ES",
	BrandAMDSevSNP:         "AMD SEV-SNP",
	BrandNekoProject:       "Neko Project II",
	BrandNoirVisor:         "NoirVisor",
	BrandQihoo:             "Qihoo 360 Sandbox",
	BrandDBVM:              "Dark Byte's VM",
	BrandUTM:               "UTM",
	BrandCompaq:            "Compaq FX!32",
	BrandInsignia:          "Insignia RealPC",
	BrandConnectix:         "Connectix Virtual PC",
	BrandContainerd:        "Containerd",
	BrandNullBrand:         "Unknown",
}

// BrandEnumToString mirrors VM::brands::brand_enum_to_string.
func BrandEnumToString(b BrandEnum) string {
	if int(b) < len(brandNames) {
		return brandNames[b]
	}
	return "Invalid"
}

// BrandElement mirrors VM::brand_element_t (a brand + its scoreboard score).
type BrandElement struct {
	Brand BrandEnum
	Score int32
}

// BrandList mirrors VM::brands::brand_list(flags): runs every technique,
// collects every brand with a non-zero score, then applies the same
// merge rules upstream applies (e.g. QEMU+KVM -> QEMU_KVM, VPC+HyperV ->
// HYPERV_VPC) before sorting by descending score.
func BrandList(flags FlagSet) []BrandElement {
	if v, ok := brandListMemo.fetch(flags); ok {
		return v
	}

	score := RunAll(flags, false)

	active := make([]BrandElement, 0, MaxBrands)
	for i := 0; i < int(MaxBrands); i++ {
		if brandScoreboard[i].score > 0 {
			active = append(active, BrandElement{Brand: brandScoreboard[i].name, Score: brandScoreboard[i].score})
		}
	}

	result := MergeBrandScores(active, score)
	brandListMemo.store(flags, result)
	return result
}

// MergeBrandScores mirrors the second half of VM::brands::brand_list: given
// every brand with a non-zero score (however they were obtained — normally
// RunAll's scoreboard, but this is deliberately a pure function of its
// inputs so it stays reusable outside a live detection run, e.g. from a
// WASM binding that only knows which techniques an external caller says
// fired) and the total score those techniques added up to, this applies the
// exact same Hyper-V/Unknown dedup, merge-rule table (QEMU+KVM -> QEMU_KVM,
// VPC+HyperV -> HYPERV_VPC, ...), and descending-score sort upstream does,
// and returns the resulting brand list.
func MergeBrandScores(active []BrandElement, totalScore uint16) []BrandElement {
	active = append([]BrandElement(nil), active...)

	remove := func(list []BrandElement, brand BrandEnum) []BrandElement {
		for i, e := range list {
			if e.Brand == brand {
				return append(list[:i], list[i+1:]...)
			}
		}
		return list
	}

	// If all brands have a score of 0, return Unknown.
	if len(active) == 0 {
		return []BrandElement{{Brand: BrandNullBrand, Score: 0}}
	}

	// If there's only a single brand, return it immediately.
	if len(active) == 1 {
		brand := active[0].Brand
		if brand == BrandHyperVRoot && totalScore > 0 {
			active = append(active, BrandElement{Brand: BrandNullBrand, Score: 0})
			active = remove(active, BrandHyperVRoot)
		}
		return active
	}

	// Remove Hyper-V root artifacts and Unknown if found alongside other brands.
	active = remove(active, BrandHyperVRoot)
	active = remove(active, BrandNullBrand)

	if len(active) == 0 {
		active = []BrandElement{{Brand: BrandNullBrand, Score: 0}}
	}

	var brandHits [MaxBrands]bool
	for _, e := range active {
		brandHits[e.Brand] = true
	}

	type mergeRule struct {
		a, b, c, result BrandEnum // c == BrandNullBrand means "unused" (a double merge)
	}

	mergeRules := []mergeRule{
		// Double merges
		{BrandVPC, BrandHyperV, BrandNullBrand, BrandHyperVVPC},

		{BrandAzureHyperV, BrandHyperV, BrandNullBrand, BrandAzureHyperV},
		{BrandAzureHyperV, BrandVPC, BrandNullBrand, BrandAzureHyperV},
		{BrandAzureHyperV, BrandHyperVVPC, BrandNullBrand, BrandAzureHyperV},

		{BrandQEMU, BrandKVM, BrandNullBrand, BrandQEMUKVM},
		{BrandKVM, BrandHyperV, BrandNullBrand, BrandKVMHyperV},
		{BrandQEMU, BrandHyperV, BrandNullBrand, BrandQEMUKVMHyperV},
		{BrandQEMUKVM, BrandHyperV, BrandNullBrand, BrandQEMUKVMHyperV},

		{BrandKVM, BrandHyperVVPC, BrandNullBrand, BrandKVMHyperV},
		{BrandQEMU, BrandHyperVVPC, BrandNullBrand, BrandQEMUKVMHyperV},
		{BrandQEMUKVM, BrandHyperVVPC, BrandNullBrand, BrandQEMUKVMHyperV},

		{BrandKVM, BrandKVMHyperV, BrandNullBrand, BrandKVMHyperV},
		{BrandQEMU, BrandKVMHyperV, BrandNullBrand, BrandQEMUKVMHyperV},
		{BrandQEMUKVM, BrandKVMHyperV, BrandNullBrand, BrandQEMUKVMHyperV},

		{BrandHyperVVPC, BrandKVMHyperV, BrandNullBrand, BrandKVMHyperV},
		{BrandHyperV, BrandKVMHyperV, BrandNullBrand, BrandKVMHyperV},
		{BrandHyperVVPC, BrandQEMUKVMHyperV, BrandNullBrand, BrandQEMUKVMHyperV},
		{BrandHyperV, BrandQEMUKVMHyperV, BrandNullBrand, BrandQEMUKVMHyperV},

		// Triple merge (retains third brand)
		{BrandQEMU, BrandKVM, BrandKVMHyperV, BrandQEMUKVMHyperV},

		// VMware merges
		{BrandVMWARE, BrandVMWAREFusion, BrandNullBrand, BrandVMWAREFusion},
		{BrandVMWARE, BrandVMWAREExpress, BrandNullBrand, BrandVMWAREExpress},
		{BrandVMWARE, BrandVMWAREESX, BrandNullBrand, BrandVMWAREESX},
		{BrandVMWARE, BrandVMWAREGSX, BrandNullBrand, BrandVMWAREGSX},
		{BrandVMWARE, BrandVMWAREWorkstation, BrandNullBrand, BrandVMWAREWorkstation},

		{BrandVMWAREHard, BrandVMWARE, BrandNullBrand, BrandVMWAREHard},
		{BrandVMWAREHard, BrandVMWAREFusion, BrandNullBrand, BrandVMWAREHard},
		{BrandVMWAREHard, BrandVMWAREExpress, BrandNullBrand, BrandVMWAREHard},
		{BrandVMWAREHard, BrandVMWAREESX, BrandNullBrand, BrandVMWAREHard},
		{BrandVMWAREHard, BrandVMWAREGSX, BrandNullBrand, BrandVMWAREHard},
		{BrandVMWAREHard, BrandVMWAREWorkstation, BrandNullBrand, BrandVMWAREHard},
	}

	currentActive := brandHits
	var activeScores [MaxBrands]int32
	for _, e := range active {
		activeScores[e.Brand] = e.Score
	}

	for _, rule := range mergeRules {
		aHit := brandHits[rule.a]
		bHit := brandHits[rule.b]
		cHit := rule.c == BrandNullBrand || brandHits[rule.c]

		if aHit && bHit && cHit {
			currentActive[rule.a] = false
			currentActive[rule.b] = false
			if rule.c != BrandNullBrand {
				currentActive[rule.c] = false
			}
			currentActive[rule.result] = true
			activeScores[rule.result] = 2 // default merged score assignment
		}
	}

	active = active[:0]
	for i := 0; i < int(MaxBrands); i++ {
		if currentActive[i] {
			active = append(active, BrandElement{Brand: BrandEnum(i), Score: activeScores[i]})
		}
	}

	if len(active) > 1 {
		sort.SliceStable(active, func(i, j int) bool {
			return active[i].Score > active[j].Score
		})
	}

	return active
}

// BrandMultipleFromList mirrors VM::brands::brand_multiple(const brand_list_t&).
func BrandMultipleFromList(list []BrandElement) string {
	buf := BrandEnumToString(list[0].Brand)
	for _, e := range list[1:] {
		buf += " or " + BrandEnumToString(e.Brand)
	}
	return buf
}

// BrandMultiple mirrors VM::brands::brand_multiple(flags).
func BrandMultiple(flags FlagSet) string {
	if v, ok := multiBrandMemo.fetch(flags); ok {
		return v
	}
	buf := BrandMultipleFromList(BrandList(flags))
	multiBrandMemo.store(flags, buf)
	return buf
}

// BrandSingleFromList mirrors VM::brands::brand_single(const brand_list_t&).
func BrandSingleFromList(list []BrandElement) BrandEnum {
	return list[0].Brand
}

// BrandSingle mirrors VM::brands::brand_single(flags).
func BrandSingle(flags FlagSet) BrandEnum {
	if v, ok := singleBrandMemo.fetch(flags); ok {
		return v
	}
	brand := BrandSingleFromList(BrandList(flags))
	singleBrandMemo.store(flags, brand)
	return brand
}
