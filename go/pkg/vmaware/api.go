package vmaware

import "fmt"

// Check mirrors VM::check(flag): runs (or fetches the cached result of) a
// single technique and returns whether it fired. Unlike the C++ version,
// which throws std::invalid_argument, invalid input is reported through the
// returned error, per normal Go convention.
func Check(flagBit EnumFlag) (bool, error) {
	if isUnsupported(flagBit) {
		cacheStore(uint16(flagBit), false, 0, BrandNullBrand)
		return false, nil
	}

	if uint8(flagBit) > EnumSize {
		return false, fmt.Errorf("vmaware: flag argument must be valid, got %d", flagBit)
	}

	if flagBit == HighThreshold || flagBit == Dynamic || flagBit == Multiple {
		return false, fmt.Errorf("vmaware: flag argument must be a technique flag and not a settings flag")
	}

	if cacheIsCached(uint16(flagBit)) {
		return cacheFetch(uint16(flagBit)).result, nil
	}

	if uint8(flagBit) >= TechniqueEnd {
		return false, nil
	}

	pair := techniqueTable[flagBit]
	if pair.Run == nil {
		return false, fmt.Errorf("vmaware: flag is not known or not implemented: %s", FlagToString(flagBit))
	}

	lastDetectedBrand = BrandNullBrand
	lastDetectedScore = 0

	result := pair.Run()
	pointsToAdd := pair.Points
	if lastDetectedScore > 0 {
		pointsToAdd = lastDetectedScore
	}

	if result {
		detectedCountNum++
	}

	if result {
		cacheStore(uint16(flagBit), true, pointsToAdd, lastDetectedBrand)
	} else {
		cacheStore(uint16(flagBit), false, 0, BrandNullBrand)
	}

	return result, nil
}

// Brand mirrors VM::brand(Args...).
func Brand(args ...EnumFlag) string {
	return BrandFlags(ArgHandler(args...))
}

// BrandFromSettings mirrors VM::brand(const settings&).
func BrandFromSettings(s *Settings) string {
	return BrandFlags(s.FlagCollector)
}

// BrandFlags mirrors VM::brand(const flagset&).
func BrandFlags(flags FlagSet) string {
	if isEnabled(flags, uint8(Multiple)) {
		return BrandMultiple(flags)
	}
	return BrandEnumToString(BrandSingle(flags))
}

// Detect mirrors VM::detect(Args...).
func Detect(args ...EnumFlag) bool {
	return DetectFlags(ArgHandler(args...))
}

// DetectFromSettings mirrors VM::detect(const settings&).
func DetectFromSettings(s *Settings) bool {
	return DetectFlags(s.FlagCollector)
}

// DetectFlags mirrors VM::detect(const flagset&).
func DetectFlags(flags FlagSet) bool {
	points := RunAll(flags, Shortcut)

	threshold := ThresholdScore
	if isEnabled(flags, uint8(HighThreshold)) {
		threshold = HighThresholdScore
	}

	return points >= threshold
}

// Percentage mirrors VM::percentage(Args...).
func Percentage(args ...EnumFlag) uint8 {
	return PercentageFlags(ArgHandler(args...))
}

// PercentageFromSettings mirrors VM::percentage(const settings&).
func PercentageFromSettings(s *Settings) uint8 {
	return PercentageFlags(s.FlagCollector)
}

// PercentageFlags mirrors VM::percentage(const flagset&).
func PercentageFlags(flags FlagSet) uint8 {
	points := RunAll(flags, Shortcut)
	return PercentageFromPoints(points, isEnabled(flags, uint8(HighThreshold)))
}

// PercentageFromPoints mirrors the threshold arithmetic inside
// VM::percentage(const flagset&), pulled out as a pure function of an
// already-computed score so it can be reused without a live detection run
// (e.g. from the browser WASM binding, which has no OS access to actually
// run techniques but can still score externally-supplied results).
func PercentageFromPoints(points uint16, highThreshold bool) uint8 {
	threshold := ThresholdScore
	if highThreshold {
		threshold = HighThresholdScore
	}

	switch {
	case points >= threshold:
		return 100
	case points >= 100:
		return 99
	default:
		if points > 99 {
			return 99
		}
		return uint8(points)
	}
}

// AddCustom mirrors VM::add_custom(percent, fn).
func AddCustom(percent uint8, run func() bool) error {
	if percent > 100 {
		return fmt.Errorf("vmaware: percentage parameter must be between 0 and 100, got %d", percent)
	}

	customTableMu.Lock()
	currentIndex := len(customTable)
	customTableMu.Unlock()

	techniqueCount++

	entry := CustomTechnique{
		Points: percent,
		ID:     uint16(BaseTechniqueCount) + uint16(currentIndex) + 1,
		Run:    run,
	}

	customTableMu.Lock()
	customTable = append(customTable, entry)
	customTableMu.Unlock()

	return nil
}

// Disable mirrors VM::DISABLE(Args...).
func Disable(args ...EnumFlag) (EnumFlag, error) {
	if err := DisabledArgHandler(args...); err != nil {
		return NullArg, err
	}
	return NullArg, nil
}

// FlagToString mirrors VM::flag_to_string.
func FlagToString(flag EnumFlag) string {
	if name, ok := flagNames[flag]; ok {
		return name
	}
	return "Unknown flag"
}

// DetectedEnums mirrors VM::detected_enums(Args...).
func DetectedEnums(args ...EnumFlag) []EnumFlag {
	return DetectedEnumsFlags(ArgHandler(args...))
}

// DetectedEnumsFromSettings mirrors VM::detected_enums(const settings&).
func DetectedEnumsFromSettings(s *Settings) []EnumFlag {
	return DetectedEnumsFlags(s.FlagCollector)
}

// DetectedEnumsFlags mirrors VM::detected_enums(const flagset&).
func DetectedEnumsFlags(flags FlagSet) []EnumFlag {
	var out []EnumFlag
	for i := TechniqueBegin; i < TechniqueEnd; i++ {
		flag := EnumFlag(i)
		if flags.Test(i) {
			if ok, _ := Check(flag); ok {
				out = append(out, flag)
			}
		}
	}
	return out
}

// DetectedCount mirrors VM::detected_count(Args...).
func DetectedCount(args ...EnumFlag) uint8 {
	return DetectedCountFlags(ArgHandler(args...))
}

// DetectedCountFromSettings mirrors VM::detected_count(const settings&).
func DetectedCountFromSettings(s *Settings) uint8 {
	return DetectedCountFlags(s.FlagCollector)
}

// DetectedCountFlags mirrors VM::detected_count(const flagset&).
func DetectedCountFlags(flags FlagSet) uint8 {
	RunAll(flags, false)
	return detectedCountNum
}

// Type mirrors VM::type(Args...).
func Type(args ...EnumFlag) string {
	return TypeFlags(ArgHandler(args...))
}

// TypeFromSettings mirrors VM::type(const settings&).
func TypeFromSettings(s *Settings) string {
	return TypeFlags(s.FlagCollector)
}

// TypeFlags mirrors VM::type(const flagset&).
func TypeFlags(flags FlagSet) string {
	return TypeFromList(BrandList(flags), isEnabled(flags, uint8(Multiple)))
}

// TypeFromList mirrors VM::type(const flagset&)'s logic pulled out as a pure
// function of an already-computed brand list, for reuse without a live
// detection run (e.g. from the browser WASM binding).
func TypeFromList(list []BrandElement, multiple bool) string {
	if multiple && len(list) > 1 {
		return "Unknown"
	}
	return TypeForBrand(BrandSingleFromList(list))
}

// TypeForBrand mirrors VM::type's brand_enum switch statement directly.
func TypeForBrand(brand BrandEnum) string {
	if t, ok := brandTypes[brand]; ok {
		return t
	}
	return "Invalid"
}

var brandTypes = map[BrandEnum]string{
	BrandXen:               "Hypervisor (Type 1)",
	BrandVMWAREESX:         "Hypervisor (Type 1)",
	BrandACRN:              "Hypervisor (Type 1)",
	BrandQNX:               "Hypervisor (Type 1)",
	BrandHyperV:            "Hypervisor (Type 2)", // to clarify you're running under a Hyper-V guest VM
	BrandAzureHyperV:       "Hypervisor (Type 1)",
	BrandKVM:               "Hypervisor (Type 1)",
	BrandKVMHyperV:         "Hypervisor (Type 1)",
	BrandQEMUKVMHyperV:     "Hypervisor (Type 1)",
	BrandQEMUKVM:           "Hypervisor (Type 1)",
	BrandIntelKGT:          "Hypervisor (Type 1)",
	BrandSimpleVisor:       "Hypervisor (Type 1)",
	BrandOpenStack:         "Hypervisor (Type 1)",
	BrandKubeVirt:          "Hypervisor (Type 1)",
	BrandPowerVM:           "Hypervisor (Type 1)",
	BrandAWSNitro:          "Hypervisor (Type 1)",
	BrandLKVM:              "Hypervisor (Type 1)",
	BrandNoirVisor:         "Hypervisor (Type 1)",
	BrandWSL:               "Hypervisor (Type 1)", // Type 1-derived lightweight VM system
	BrandDBVM:              "Hypervisor (Type 1)",
	BrandBHYVE:             "Hypervisor (Type 2)",
	BrandVBOX:              "Hypervisor (Type 2)",
	BrandVMWARE:            "Hypervisor (Type 2)",
	BrandVMWAREExpress:     "Hypervisor (Type 2)",
	BrandVMWAREGSX:         "Hypervisor (Type 2)",
	BrandVMWAREWorkstation: "Hypervisor (Type 2)",
	BrandVMWAREFusion:      "Hypervisor (Type 2)",
	BrandParallels:         "Hypervisor (Type 2)",
	BrandVPC:               "Hypervisor (Type 2)",
	BrandNVMM:              "Hypervisor (Type 2)",
	BrandBSDVMM:            "Hypervisor (Type 2)",
	BrandHyperVVPC:         "Hypervisor (Type 2)",
	BrandVMWAREHard:        "Hypervisor (Type 2)",
	BrandUTM:               "Hypervisor (Type 2)",
	BrandIntelHAXM:         "Hosted hypervisor / accelerator (Type 2)",
	BrandCuckoo:            "Sandbox",
	BrandSandboxie:         "Sandbox",
	BrandHybrid:            "Sandbox",
	BrandCWSandbox:         "Sandbox",
	BrandJoebox:            "Sandbox",
	BrandAnubis:            "Sandbox",
	BrandComodo:            "Sandbox",
	BrandThreatExpert:      "Sandbox",
	BrandQihoo:             "Sandbox",
	BrandBochs:             "Emulator",
	BrandBluestacks:        "Emulator",
	BrandNekoProject:       "Emulator",
	BrandCompaq:            "Emulator",
	BrandInsignia:          "Emulator",
	BrandConnectix:         "Emulator",
	BrandQEMU:              "Emulator/Hypervisor (Type 2)",
	BrandJailhouse:         "Partitioning Hypervisor",
	BrandUnisys:            "Partitioning Hypervisor",
	BrandDocker:            "Container",
	BrandPodman:            "Container",
	BrandOpenVZ:            "Container",
	BrandContainerd:        "Container",
	BrandLMHS:              "Hypervisor (unknown type)",
	BrandWine:              "Compatibility layer",
	BrandIntelTDX:          "Trusted Domain",
	BrandAppleVZ:           "Unknown",
	BrandUML:               "Paravirtualised/Hypervisor (Type 2)",
	BrandAMDSev:            "VM encryptor",
	BrandAMDSevES:          "VM encryptor",
	BrandAMDSevSNP:         "VM encryptor",
	BrandGCE:               "Cloud VM service",
	BrandBarevisor:         "Hypervisor (Type 1)",
	BrandHyperPlatform:     "Hypervisor (Type 1)",
	BrandMiniVisor:         "Hypervisor (Type 1)",
	// This refers to the Type 1 hypervisor Windows normally runs under; we
	// report "Host machine" to clarify this isn't a traditional guest VM.
	BrandHyperVRoot: "Host machine",
	BrandNullBrand:  "Unknown",
}

// Conclusion mirrors VM::conclusion(Args...).
func Conclusion(args ...EnumFlag) string {
	return ConclusionFlags(ArgHandler(args...))
}

// ConclusionFromSettings mirrors VM::conclusion(const settings&).
func ConclusionFromSettings(s *Settings) string {
	return ConclusionFlags(s.FlagCollector)
}

// ConclusionFlags mirrors VM::conclusion(const flagset&).
func ConclusionFlags(flags FlagSet) string {
	if v, ok := conclusionMemo.fetch(flags); ok {
		return v
	}

	percent := PercentageFlags(flags)
	list := BrandList(flags)
	result := ConclusionFromResult(percent, list, isEnabled(flags, uint8(Dynamic)), isEnabled(flags, uint8(Multiple)))

	conclusionMemo.store(flags, result)
	return result
}

// grammaticalArticleExceptions mirrors the "a"/"an" grammar fix upstream
// applies so the conclusion never reads "an VirtualBox" or "a Anubis".
var grammaticalArticleExceptions = map[BrandEnum]bool{
	BrandACRN:      true,
	BrandAnubis:    true,
	BrandBSDVMM:    true,
	BrandIntelHAXM: true,
	BrandAppleVZ:   true,
	BrandIntelKGT:  true,
	BrandPowerVM:   true,
	BrandOpenStack: true,
	BrandAWSNitro:  true,
	BrandOpenVZ:    true,
	BrandIntelTDX:  true,
	BrandAMDSev:    true,
	BrandAMDSevES:  true,
	BrandAMDSevSNP: true,
	BrandNullBrand: true,
}

// ConclusionFromResult mirrors VM::conclusion(const flagset&)'s wording
// logic, pulled out as a pure function of an already-computed percentage
// and brand list so it can be reused without a live detection run (e.g.
// from the browser WASM binding).
func ConclusionFromResult(percent uint8, list []BrandElement, dynamic bool, multiple bool) string {
	const (
		veryUnlikely = "Very unlikely"
		unlikely     = "Unlikely"
		potentially  = "Potentially"
		might        = "Might be"
		likely       = "Likely"
		veryLikely   = "Very likely"
		insideVM     = "Running inside"
	)

	makeConclusion := func(category string) string {
		firstBrand := BrandSingleFromList(list)

		addition := " a "
		if grammaticalArticleExceptions[firstBrand] {
			addition = " an "
		}

		var brandStr string
		if firstBrand == BrandNullBrand {
			// Avoid the capitalized "an Unknown".
			brandStr = "unknown"
		} else if multiple {
			brandStr = BrandMultipleFromList(list)
		} else {
			brandStr = BrandEnumToString(firstBrand)
		}

		suffix := " VM"
		if firstBrand == BrandHyperVRoot {
			// Hyper-V root artifacts are an exception given how unique the
			// circumstance is (it's the host, not a guest).
			suffix = ""
		}

		return category + addition + brandStr + suffix
	}

	if dynamic {
		switch {
		case percent == 0:
			return "Running on bare metal"
		case percent <= 20:
			return makeConclusion(veryUnlikely)
		case percent <= 35:
			return makeConclusion(unlikely)
		case percent < 50:
			return makeConclusion(potentially)
		case percent <= 62:
			return makeConclusion(might)
		case percent <= 75:
			return makeConclusion(likely)
		case percent < 100:
			return makeConclusion(veryLikely)
		}
	}

	if percent == 100 {
		return makeConclusion(insideVM)
	}

	return "Running on bare metal"
}

// VMAware mirrors VM::vmaware: a single struct snapshotting every result at
// once.
type VMAware struct {
	Brand                    string
	Type                     string
	Conclusion               string
	IsVM                     bool
	Percentage               uint8
	DetectedCount            uint8
	TechniqueCount           uint16
	DetectedTechniques       []EnumFlag
	DetectedTechniqueStrings []string
	DisabledTechniques       []EnumFlag
}

// NewVMAware mirrors the VM::vmaware constructor(s).
func NewVMAware(args ...EnumFlag) *VMAware {
	return NewVMAwareFlags(ArgHandler(args...))
}

// NewVMAwareFlags mirrors VM::vmaware(const flagset&).
func NewVMAwareFlags(flags FlagSet) *VMAware {
	v := &VMAware{}
	v.Brand = BrandFlags(flags)
	v.Type = TypeFlags(flags)
	v.Conclusion = ConclusionFlags(flags)
	v.IsVM = DetectFlags(flags)
	v.Percentage = PercentageFlags(flags)
	v.DetectedCount = DetectedCountFlags(flags)
	v.TechniqueCount = techniqueCount
	v.DetectedTechniques = DetectedEnumsFlags(flags)

	v.DetectedTechniqueStrings = make([]string, 0, len(v.DetectedTechniques))
	for _, t := range v.DetectedTechniques {
		v.DetectedTechniqueStrings = append(v.DetectedTechniqueStrings, FlagToString(t))
	}

	v.DisabledTechniques = DisabledTechniques

	return v
}
