//go:build linux || wasip1

package vmaware

import "testing"

// TestLinuxTechniquesDoNotPanic runs every technique flag registered for
// Linux (the cross-platform CPU set plus the full Linux file/proc/sysfs
// set) individually through Check and asserts only that none of them panic
// or error — this is deliberately not asserting *results*, since those
// depend on the machine running the test.
func TestLinuxTechniquesDoNotPanic(t *testing.T) {
	for i := TechniqueBegin; i < TechniqueEnd; i++ {
		flag := EnumFlag(i)
		if techniqueTable[i].Run == nil {
			continue
		}

		t.Run(FlagToString(flag), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Check(%s) panicked: %v", FlagToString(flag), r)
				}
			}()

			if _, err := Check(flag); err != nil {
				t.Fatalf("Check(%s) returned an error: %v", FlagToString(flag), err)
			}
		})
	}
}

// TestLinuxRealHardwareIsKVM pins down the one fact we know for certain
// about the container this port was developed and tested against: it is a
// KVM guest. If this ever starts failing, either the detection engine
// regressed or the CI environment changed — worth knowing either way.
func TestLinuxRealHardwareIsKVM(t *testing.T) {
	resetMemoCaches()

	brand := Brand(All)
	if brand != "KVM" {
		t.Skipf("this container is expected to be a KVM guest (got brand %q) — skipping instead of failing, since a future CI environment may genuinely differ", brand)
	}

	if pct := Percentage(All); pct != 100 {
		t.Errorf("Percentage(All) = %d, want 100 on a KVM guest", pct)
	}
	if !Detect(All) {
		t.Errorf("Detect(All) = false, want true on a KVM guest")
	}
}
