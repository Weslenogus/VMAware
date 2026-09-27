package vmaware

import "testing"

func TestFlagSetBasics(t *testing.T) {
	var f FlagSet

	if f.Any() {
		t.Fatalf("zero-value FlagSet should have no bits set")
	}
	if !f.None() {
		t.Fatalf("zero-value FlagSet should report None() == true")
	}

	f.Set(uint8(VMID))
	if !f.Test(uint8(VMID)) {
		t.Fatalf("Set then Test should report true")
	}
	if !f.Any() {
		t.Fatalf("FlagSet with a bit set should report Any() == true")
	}

	f.Reset(uint8(VMID))
	if f.Test(uint8(VMID)) {
		t.Fatalf("Reset should clear the bit")
	}

	// Out-of-range bits should never panic and should read as false.
	if f.Test(255) {
		t.Fatalf("out-of-range Test should return false, not panic")
	}
	f.Set(255) // must not panic
}

func TestFlagSetValueSemantics(t *testing.T) {
	// FlagSet is a fixed-size array, so assignment must copy, not alias —
	// this is load-bearing for RunAll's scoreboard snapshot/rollback.
	var a FlagSet
	a.Set(uint8(VMID))

	b := a
	b.Set(uint8(CPUBrand))

	if a.Test(uint8(CPUBrand)) {
		t.Fatalf("assigning a FlagSet must copy by value, not alias")
	}
	if !b.Test(uint8(VMID)) || !b.Test(uint8(CPUBrand)) {
		t.Fatalf("copy should retain the original bit and gain the new one")
	}
}

func TestGenerateDefaultExcludesSettingsBits(t *testing.T) {
	flags := GenerateDefault()

	for _, bit := range []EnumFlag{Experimental, HighThreshold, NullArg, Dynamic, Multiple, All} {
		if flags.Test(uint8(bit)) {
			t.Errorf("GenerateDefault() should not set %s", FlagToString(bit))
		}
	}

	// Every technique flag should be enabled by default (barring anything
	// pushed onto DisabledTechniques by an earlier test/CLI run).
	if !flags.Test(uint8(VMID)) {
		t.Errorf("GenerateDefault() should enable VMID by default")
	}
}

func TestArgHandlerExpandsDefaultAndAll(t *testing.T) {
	only := ArgHandler(VMID)
	if !only.Test(uint8(VMID)) {
		t.Fatalf("ArgHandler(VMID) should set the VMID bit")
	}
	// A single technique flag with no DEFAULT/ALL should NOT pull in every
	// other technique (are_techniques_empty only fires when the collector
	// has zero technique bits set).
	if only.Test(uint8(CPUBrand)) {
		t.Fatalf("ArgHandler(VMID) should not also enable unrelated techniques")
	}

	withHighThreshold := ArgHandler(VMID, HighThreshold)
	if !withHighThreshold.Test(uint8(HighThreshold)) {
		t.Fatalf("ArgHandler should preserve settings flags like HighThreshold")
	}

	allFlags := ArgHandler(All)
	if !allFlags.Test(uint8(VMID)) || !allFlags.Test(uint8(CPUBrand)) {
		t.Fatalf("ArgHandler(All) should enable every technique")
	}
}

func TestPercentageFromPoints(t *testing.T) {
	cases := []struct {
		points        uint16
		highThreshold bool
		want          uint8
	}{
		{0, false, 0},
		{99, false, 99},
		{100, false, 99},
		{149, false, 99},
		{150, false, 100},
		{299, true, 99},
		{300, true, 100},
	}

	for _, c := range cases {
		if got := PercentageFromPoints(c.points, c.highThreshold); got != c.want {
			t.Errorf("PercentageFromPoints(%d, %v) = %d, want %d", c.points, c.highThreshold, got, c.want)
		}
	}
}

func TestMergeBrandScoresSingleBrand(t *testing.T) {
	list := MergeBrandScores([]BrandElement{{Brand: BrandKVM, Score: 3}}, 100)
	if len(list) != 1 || list[0].Brand != BrandKVM {
		t.Fatalf("single active brand should be returned as-is, got %+v", list)
	}
}

func TestMergeBrandScoresEmptyIsUnknown(t *testing.T) {
	list := MergeBrandScores(nil, 0)
	if len(list) != 1 || list[0].Brand != BrandNullBrand {
		t.Fatalf("no active brands should merge to [NullBrand], got %+v", list)
	}
}

func TestMergeBrandScoresQEMUKVM(t *testing.T) {
	list := MergeBrandScores([]BrandElement{
		{Brand: BrandQEMU, Score: 1},
		{Brand: BrandKVM, Score: 1},
	}, 50)

	if len(list) != 1 || list[0].Brand != BrandQEMUKVM {
		t.Fatalf("QEMU+KVM should merge into QEMU_KVM, got %+v", list)
	}
}

func TestMergeBrandScoresHyperVRootAlone(t *testing.T) {
	// A lone HYPERV_ROOT hit alongside a nonzero total score should be
	// paired with NULL_BRAND (mirrors upstream's "prevent false positives"
	// comment on brand_list()).
	list := MergeBrandScores([]BrandElement{{Brand: BrandHyperVRoot, Score: 1}}, 10)

	foundNull := false
	for _, e := range list {
		if e.Brand == BrandNullBrand {
			foundNull = true
		}
	}
	if !foundNull {
		t.Fatalf("lone HyperVRoot with score>0 should add NullBrand, got %+v", list)
	}
}

func TestTypeForBrandKnownAndUnknown(t *testing.T) {
	if got := TypeForBrand(BrandQEMU); got != "Emulator/Hypervisor (Type 2)" {
		t.Errorf("TypeForBrand(BrandQEMU) = %q", got)
	}
	if got := TypeForBrand(BrandNullBrand); got != "Unknown" {
		t.Errorf("TypeForBrand(BrandNullBrand) = %q, want Unknown", got)
	}
}

func TestConclusionFromResultBareMetal(t *testing.T) {
	list := []BrandElement{{Brand: BrandNullBrand, Score: 0}}
	if got := ConclusionFromResult(0, list, false, false); got != "Running on bare metal" {
		t.Errorf("ConclusionFromResult(0, ...) = %q", got)
	}
}

func TestConclusionFromResultInsideVM(t *testing.T) {
	list := []BrandElement{{Brand: BrandKVM, Score: 3}}
	got := ConclusionFromResult(100, list, false, false)
	want := "Running inside a KVM VM"
	if got != want {
		t.Errorf("ConclusionFromResult(100, KVM, ...) = %q, want %q", got, want)
	}
}

func TestConclusionFromResultGrammarException(t *testing.T) {
	// ACRN is in the "an" exception list.
	list := []BrandElement{{Brand: BrandACRN, Score: 3}}
	got := ConclusionFromResult(100, list, false, false)
	want := "Running inside an ACRN VM"
	if got != want {
		t.Errorf("ConclusionFromResult(100, ACRN, ...) = %q, want %q", got, want)
	}
}

func TestEvaluateExternal(t *testing.T) {
	results := []ExternalResult{
		{Points: 100, Brand: BrandKVM, ExtraBrand: BrandNullBrand},
		{Points: 95, Brand: BrandKVM, ExtraBrand: BrandNullBrand},
	}

	got := EvaluateExternal(results, EvalOptions{})

	if !got.IsVM {
		t.Errorf("200 points should clear the default 150 threshold")
	}
	if got.Percentage != 100 {
		t.Errorf("Percentage = %d, want 100", got.Percentage)
	}
	if got.Brand != "KVM" {
		t.Errorf("Brand = %q, want KVM", got.Brand)
	}
	if got.Type != "Hypervisor (Type 1)" {
		t.Errorf("Type = %q", got.Type)
	}
}

func TestEvaluateExternalNoSignal(t *testing.T) {
	got := EvaluateExternal(nil, EvalOptions{})
	if got.IsVM {
		t.Errorf("no results should never report a VM")
	}
	if got.Brand != "Unknown" {
		t.Errorf("Brand = %q, want Unknown", got.Brand)
	}
	if got.Conclusion != "Running on bare metal" {
		t.Errorf("Conclusion = %q", got.Conclusion)
	}
}

func TestIsUnsupportedCrossPlatformRangeAlwaysSupported(t *testing.T) {
	for f := HypervisorBit; f <= KGTSignature; f++ {
		if isUnsupported(f) {
			t.Errorf("%s is in the cross-platform range and must never be unsupported", FlagToString(f))
		}
	}
}

func TestFlagToStringExperimentalIsUnknown(t *testing.T) {
	// Upstream's flag_to_string switch has no case for EXPERIMENTAL — this
	// is a faithfully-preserved quirk, not a bug, see flag_names.go.
	if got := FlagToString(Experimental); got != "Unknown flag" {
		t.Errorf("FlagToString(Experimental) = %q, want %q (upstream omission preserved on purpose)", got, "Unknown flag")
	}
}
