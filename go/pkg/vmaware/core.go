package vmaware

import (
	"fmt"
	"sync"
)

// Technique mirrers VM::core::technique: a certainty score (0-100) plus the
// technique function itself. Run == nil mirrors an empty/unregistered table
// slot (the C++ "technique_data.run == nullptr" skip case).
type Technique struct {
	Points uint8
	Run    func() bool
}

// techniqueTable mirrors VM::core::technique_table (an array sized
// enum_size+1, indexed directly by the EnumFlag). Each platform-tagged file
// (techniques_linux.go, techniques_windows.go, ...) populates its own
// entries from an init() func, mirroring the #if-guarded initializer list at
// the bottom of vmaware.hpp.
var techniqueTable [NumFlags]Technique

// RegisterTechnique installs (or overwrites) a technique's table entry.
// Called from each platform file's init().
func RegisterTechnique(id EnumFlag, points uint8, run func() bool) {
	techniqueTable[id] = Technique{Points: points, Run: run}
}

// CustomTechnique mirrors VM::core::custom_technique.
type CustomTechnique struct {
	Points uint8
	ID     uint16
	Run    func() bool
}

var (
	customTableMu sync.Mutex
	customTable   []CustomTechnique
)

// brandScoreboardEntry mirrors VM::core::brand_entry.
type brandScoreboardEntry struct {
	name  BrandEnum
	score int32
}

var brandScoreboard [MaxBrands]brandScoreboardEntry

// lastDetectedBrand/lastDetectedScore mirror VM::core::last_detected_brand
// and VM::core::last_detected_score: scratch space a technique function
// writes to (via Add/AddScore) so RunAll can pick up which brand/score
// override it wants to report, exactly like the C++ globals.
var (
	lastDetectedBrand = BrandNullBrand
	lastDetectedScore uint8
)

// Add mirrors the 3 VM::core::add overloads, dispatched by which arguments
// are BrandNullBrand.
func Add(brand BrandEnum) bool { return AddScore(brand, BrandNullBrand, 0) }

// AddWithScore mirrors VM::core::add(brand, score).
func AddWithScore(brand BrandEnum, score uint8) bool { return AddScore(brand, BrandNullBrand, score) }

// AddTwo mirrors VM::core::add(brand, extraBrand).
func AddTwo(brand, extraBrand BrandEnum) bool { return AddScore(brand, extraBrand, 0) }

// AddScore mirrors VM::core::add_score.
func AddScore(brand, extraBrand BrandEnum, score uint8) bool {
	if brand != BrandNullBrand {
		lastDetectedBrand = brand
	} else if extraBrand != BrandNullBrand {
		lastDetectedBrand = extraBrand
	}

	if score > 0 {
		lastDetectedScore = score
	}

	if int(brand) < len(brandScoreboard) && brand != BrandNullBrand {
		brandScoreboard[brand].score++
	}
	if extraBrand != BrandNullBrand && int(extraBrand) < len(brandScoreboard) {
		brandScoreboard[extraBrand].score++
	}

	return true
}

// isDisabled/isEnabled mirror VM::core::is_disabled/is_enabled.
func isDisabled(flags FlagSet, bit uint8) bool {
	return int(bit) >= len(flags) || !flags[bit]
}

func isEnabled(flags FlagSet, bit uint8) bool {
	return int(bit) < len(flags) && flags[bit]
}

var techniquesMask = func() FlagSet {
	var m FlagSet
	for i := TechniqueBegin; i < TechniqueEnd; i++ {
		m.Set(i)
	}
	return m
}()

var settingsMask = func() FlagSet {
	var m FlagSet
	for i := SettingsBegin; i < SettingsEnd; i++ {
		m.Set(i)
	}
	return m
}()

func areTechniquesEmpty(flags FlagSet) bool {
	return flags.And(techniquesMask).None()
}

func isSettingFlagSet(flags FlagSet) bool {
	return flags.And(settingsMask).Any()
}

// detectedCountNum mirrors VM::detected_count_num.
var detectedCountNum uint8

// technique_count mirrors VM::technique_count.
var techniqueCount = BaseTechniqueCount

// RunAll mirrors VM::core::run_all: runs every enabled, non-cached technique
// in the table (plus any custom techniques), accumulating points and the
// brand scoreboard, and returns the total score. Matches the upstream
// snapshot/rollback-on-false and cache/shortcut behavior exactly.
func RunAll(flags FlagSet, shortcut bool) uint16 {
	var points uint16
	detectedCountNum = 0

	for i := 0; i < int(MaxBrands); i++ {
		brandScoreboard[i] = brandScoreboardEntry{name: BrandEnum(i), score: 0}
	}

	thresholdPoints := ThresholdScore
	if isEnabled(flags, uint8(HighThreshold)) {
		thresholdPoints = HighThresholdScore
	}

	for i := TechniqueBegin; i < TechniqueEnd; i++ {
		techniqueMacro := EnumFlag(i)
		techniqueData := techniqueTable[i]

		if techniqueData.Run == nil {
			continue
		}
		if isDisabled(flags, i) {
			continue
		}

		if cacheIsCached(uint16(techniqueMacro)) {
			data := cacheFetch(uint16(techniqueMacro))
			if data.result {
				points += uint16(data.points)
				detectedCountNum++
				if data.brand != BrandNullBrand {
					Add(data.brand)
				}
			}
			if shortcut && points >= thresholdPoints {
				return points
			}
			continue
		}

		lastDetectedBrand = BrandNullBrand
		lastDetectedScore = 0

		scoreboardSnapshot := brandScoreboard

		result := techniqueData.Run()

		if result {
			pointsToAdd := techniqueData.Points
			if lastDetectedScore > 0 {
				pointsToAdd = lastDetectedScore
			}

			points += uint16(pointsToAdd)
			detectedCountNum++

			detectedBrand := lastDetectedBrand
			cacheStore(uint16(techniqueMacro), true, pointsToAdd, detectedBrand)
		} else {
			brandScoreboard = scoreboardSnapshot
			lastDetectedBrand = BrandNullBrand
			lastDetectedScore = 0
			cacheStore(uint16(techniqueMacro), false, 0, BrandNullBrand)
		}

		if shortcut && points >= thresholdPoints {
			return points
		}
	}

	customTableMu.Lock()
	custom := make([]CustomTechnique, len(customTable))
	copy(custom, customTable)
	customTableMu.Unlock()

	if len(custom) > 0 {
		for _, technique := range custom {
			if shortcut && points >= thresholdPoints {
				return points
			}
			if technique.Run == nil {
				continue
			}

			if cacheIsCached(technique.ID) {
				data := cacheFetch(technique.ID)
				if data.result {
					points += uint16(data.points)
					detectedCountNum++
					if data.brand != BrandNullBrand {
						Add(data.brand)
					}
				}
				if shortcut && points >= thresholdPoints {
					return points
				}
				continue
			}

			lastDetectedBrand = BrandNullBrand
			lastDetectedScore = 0

			scoreboardSnapshot := brandScoreboard

			result := technique.Run()

			if result {
				pointsToAdd := technique.Points
				if lastDetectedScore > 0 {
					pointsToAdd = lastDetectedScore
				}

				points += uint16(pointsToAdd)
				detectedCountNum++

				detectedBrand := lastDetectedBrand
				cacheStore(technique.ID, true, pointsToAdd, detectedBrand)
			} else {
				brandScoreboard = scoreboardSnapshot
				lastDetectedBrand = BrandNullBrand
				lastDetectedScore = 0
				cacheStore(technique.ID, false, 0, BrandNullBrand)
			}
		}
	}

	return points
}

// Settings mirrors VM::core::settings, the builder-style alternative to
// passing a flag list directly.
type Settings struct {
	FlagCollector FlagSet
}

// NewSettings mirrors the settings default member initializer.
func NewSettings() *Settings {
	return &Settings{FlagCollector: GenerateDefault()}
}

// Enable mirrors settings::enable.
func (s *Settings) Enable(flag EnumFlag) {
	switch flag {
	case All:
		s.FlagCollector.Or(GenerateAll())
	case Default:
		s.FlagCollector.Or(GenerateDefault())
	case Experimental:
		DisableExperimentalTechniquesIn(&s.FlagCollector)
	default:
		s.FlagCollector.SetValue(uint8(flag), true)
	}
}

// Disable mirrors settings::disable.
func (s *Settings) Disable(flag EnumFlag) {
	s.FlagCollector.Reset(uint8(flag))
}

// IsSet mirrors settings::is_set.
func (s *Settings) IsSet(flag EnumFlag) bool {
	return s.FlagCollector.Test(uint8(flag))
}

var defaultFlagsOnce sync.Once
var defaultFlagsCache FlagSet

// GenerateDefault mirrors VM::core::generate_default(): every technique
// enabled except the ones in DisabledTechniques, with every settings bit
// (other than the implicit default) cleared.
func GenerateDefault() FlagSet {
	defaultFlagsOnce.Do(func() {
		var f FlagSet
		f.SetAll()

		for _, id := range DisabledTechniques {
			f.Reset(uint8(id))
		}

		f.Reset(uint8(Experimental))
		f.Reset(uint8(HighThreshold))
		f.Reset(uint8(NullArg))
		f.Reset(uint8(Dynamic))
		f.Reset(uint8(Multiple))
		f.Reset(uint8(All))

		defaultFlagsCache = f
	})
	return defaultFlagsCache
}

// GenerateAll mirrors VM::core::generate_all(): the default set, plus every
// technique that DisabledTechniques had turned off, re-enabled.
func GenerateAll() FlagSet {
	flags := GenerateDefault()
	for _, technique := range DisabledTechniques {
		flags.Set(uint8(technique))
	}
	return flags
}

var (
	flagCollectorMu       sync.Mutex
	disabledFlagCollector FlagSet
)

// ResetDisabledFlagset mirrors VM::core::reset_disabled_flagset.
func ResetDisabledFlagset() {
	flagCollectorMu.Lock()
	defer flagCollectorMu.Unlock()
	disabledFlagCollector.ResetAll()
	for _, technique := range DisabledTechniques {
		disabledFlagCollector.Set(uint8(technique))
	}
}

// DisableExperimentalTechniquesIn mirrors VM::core::disable_experimental_techniques(flags&).
func DisableExperimentalTechniquesIn(flags *FlagSet) {
	for _, technique := range ExperimentalTechniques {
		flags.Reset(uint8(technique))
	}
}

// DisableExperimentalTechniques mirrors the no-arg overload, which marks the
// experimental techniques in the process-wide disabled collector instead.
func DisableExperimentalTechniques() {
	flagCollectorMu.Lock()
	defer flagCollectorMu.Unlock()
	for _, technique := range ExperimentalTechniques {
		disabledFlagCollector.Set(uint8(technique))
	}
}

// ArgHandler mirrors VM::core::arg_handler(Args...): collects the given
// flags into a FlagSet, then expands DEFAULT/ALL/EXPERIMENTAL and applies
// anything queued up by a prior Disable() call.
func ArgHandler(args ...EnumFlag) FlagSet {
	var collector FlagSet
	if len(args) == 0 {
		flagCollectorMu.Lock()
		defer flagCollectorMu.Unlock()
		collector = GenerateDefault()
		collector.AndNot(disabledFlagCollector)
		disabledFlagCollector.ResetAll()
		return collector
	}

	for _, a := range args {
		collector.Set(uint8(a))
	}

	if collector.Test(uint8(Default)) {
		collector.Or(GenerateDefault())
		collector.Reset(uint8(Default))
	}

	if areTechniquesEmpty(collector) {
		collector.Or(GenerateDefault())
	}

	if collector.Test(uint8(All)) {
		collector.Or(GenerateAll())
		collector.Reset(uint8(All))
	}

	if collector.Test(uint8(Experimental)) {
		DisableExperimentalTechniquesIn(&collector)
		collector.Reset(uint8(Experimental))
	}

	flagCollectorMu.Lock()
	collector.AndNot(disabledFlagCollector)
	disabledFlagCollector.ResetAll()
	flagCollectorMu.Unlock()

	return collector
}

// DisabledArgHandler mirrors VM::core::disabled_arg_handler, used by
// DISABLE(). Unlike the C++ version (which throws), it returns an error.
func DisabledArgHandler(args ...EnumFlag) error {
	if len(args) == 0 {
		return fmt.Errorf("vmaware: DISABLE() must contain at least one flag")
	}

	var temp FlagSet
	for _, a := range args {
		temp.Set(uint8(a))
	}

	if isSettingFlagSet(temp) {
		return fmt.Errorf("vmaware: DISABLE() must not contain a settings flag, they are disabled by default anyway")
	}

	flagCollectorMu.Lock()
	disabledFlagCollector.Or(temp)
	flagCollectorMu.Unlock()

	return nil
}
