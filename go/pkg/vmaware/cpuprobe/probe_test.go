package cpuprobe

import (
	"runtime"
	"testing"
)

func TestCPUIDBasicInfoHasVendorOnX86(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("CPUID only exists on x86")
	}

	_, ebx, ecx, edx := CPUID(LeafBasicInfo)
	if ebx == 0 && ecx == 0 && edx == 0 {
		t.Fatalf("CPUID(LeafBasicInfo) returned an all-zero vendor string on a real x86 CPU")
	}
}

func TestCPUIDNonX86ReturnsZero(t *testing.T) {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		t.Skip("this test only makes sense on non-x86 (or WASM) targets")
	}

	eax, ebx, ecx, edx := CPUID(LeafBasicInfo)
	if eax != 0 || ebx != 0 || ecx != 0 || edx != 0 {
		t.Fatalf("CPUID should be an all-zero no-op off x86, got %08x %08x %08x %08x", eax, ebx, ecx, edx)
	}
}

func TestIsAMDAndIsIntelAreMutuallyExclusive(t *testing.T) {
	if IsAMD() && IsIntel() {
		t.Fatalf("a CPU cannot report both AuthenticAMD and GenuineIntel vendor signatures")
	}
}

func TestGetBrandNeverPanics(t *testing.T) {
	brand := GetBrand()
	if brand == "" {
		t.Fatalf("GetBrand() should return \"Unknown\" rather than an empty string when unsupported")
	}
}

func TestIsLeafSupportedIsCached(t *testing.T) {
	// Calling twice must be safe (exercises the leaf cache) and consistent.
	a := IsLeafSupported(LeafFeatures)
	b := IsLeafSupported(LeafFeatures)
	if a != b {
		t.Fatalf("IsLeafSupported should be stable across calls, got %v then %v", a, b)
	}
}

func TestCPUManufacturerRejectsArbitraryLeaves(t *testing.T) {
	if got := CPUManufacturer(LeafFeatures); got != "" {
		t.Fatalf("CPUManufacturer should only accept LeafHypervisor/LeafHvEnlightenment, got %q for LeafFeatures", got)
	}
}

func TestIsCeleronRequiresIntel(t *testing.T) {
	if IsAMD() && IsCeleron(SteppingInfo{Model: 0xA, Family: 0x6, ExtModel: 0x2}) {
		t.Fatalf("IsCeleron must be false on a non-Intel CPU regardless of the stepping bits")
	}
}
