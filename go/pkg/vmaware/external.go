package vmaware

// ExternalResult describes one technique's outcome as reported by a caller
// that ran the actual detection itself — this is what EvaluateExternal
// consumes. It exists for hosts (most notably the browser WASM build, see
// wasm/browser) that cannot execute the real OS-probing technique functions
// themselves (a browser sandbox has no CPUID, filesystem, or registry
// access) but still want VMAware's scoring, brand-merging, and wording
// logic applied to signals gathered some other way.
type ExternalResult struct {
	// Points is the certainty score this technique contributes if it fired
	// (mirrors a technique_table entry's Points, or the score argument to
	// VM::core::add_score).
	Points uint8
	// Brand is the primary brand this technique attributes, or
	// BrandNullBrand if it doesn't attribute one (mirrors VM::core::add's
	// p_brand argument).
	Brand BrandEnum
	// ExtraBrand is an optional second brand attribution (mirrors
	// VM::core::add's two-brand overload, e.g. Azure Hyper-V techniques
	// crediting both Azure and Hyper-V). BrandNullBrand means unused.
	ExtraBrand BrandEnum
}

// EvalOptions mirrors the settings bits that affect Detect/Percentage/Type/
// Conclusion (HighThreshold, Dynamic, Multiple).
type EvalOptions struct {
	HighThreshold bool
	Dynamic       bool
	Multiple      bool
}

// EvalResult is the full VM::vmaware-equivalent bundle EvaluateExternal
// produces.
type EvalResult struct {
	IsVM       bool
	Percentage uint8
	Type       string
	Brand      string
	Conclusion string
	BrandList  []BrandElement
}

// EvaluateExternal mirrors the whole VM::vmaware pipeline (score -> brand
// scoreboard -> merge -> percentage/type/conclusion) as a pure function of
// externally-supplied technique results, instead of running RunAll against
// live technique functions. Every technique in results is treated as having
// fired (a caller should simply omit techniques that didn't).
func EvaluateExternal(results []ExternalResult, opts EvalOptions) EvalResult {
	var totalScore uint16
	var scoreboard [MaxBrands]int32

	addBrand := func(b BrandEnum) {
		if b != BrandNullBrand && int(b) < len(scoreboard) {
			scoreboard[b]++
		}
	}

	for _, r := range results {
		totalScore += uint16(r.Points)
		addBrand(r.Brand)
		addBrand(r.ExtraBrand)
	}

	active := make([]BrandElement, 0, MaxBrands)
	for i := 0; i < int(MaxBrands); i++ {
		if scoreboard[i] > 0 {
			active = append(active, BrandElement{Brand: BrandEnum(i), Score: scoreboard[i]})
		}
	}

	list := MergeBrandScores(active, totalScore)

	threshold := ThresholdScore
	if opts.HighThreshold {
		threshold = HighThresholdScore
	}

	percentage := PercentageFromPoints(totalScore, opts.HighThreshold)
	isVM := totalScore >= threshold
	typ := TypeFromList(list, opts.Multiple)

	var brand string
	if opts.Multiple {
		brand = BrandMultipleFromList(list)
	} else {
		brand = BrandEnumToString(BrandSingleFromList(list))
	}

	conclusion := ConclusionFromResult(percentage, list, opts.Dynamic, opts.Multiple)

	return EvalResult{
		IsVM:       isVM,
		Percentage: percentage,
		Type:       typ,
		Brand:      brand,
		Conclusion: conclusion,
		BrandList:  list,
	}
}
