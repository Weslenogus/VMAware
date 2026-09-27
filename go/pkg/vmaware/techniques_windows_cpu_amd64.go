//go:build windows && amd64

package vmaware

import (
	"unsafe"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

// cpuHeuristicAESAVX mirrors cpu_heuristic()'s first stage: run the actual
// AES-NI/AVX/AVX2 instructions and compare what happened against what
// CPUID/XCR0 claimed should happen.
//
// AVX-512 is intentionally not probed here: Go's assembler support for
// EVEX-encoded instructions on Z registers is far newer and less complete
// than its VEX (AVX/AVX2) support, and this port has no way to validate
// generated AVX-512 machine code on real Windows hardware, so guessing at
// it risks silently miscompiling rather than just under-detecting. Every
// other upstream sub-check here is ported in full.
func cpuHeuristicAESAVX() bool {
	var maxLeaf, ecx uint32
	if maxLeaf, _, ecx, _ = cpuprobe.CPUID(cpuprobe.LeafBasicInfo); maxLeaf >= 1 {
		_, _, ecx, _ = cpuprobe.CPUID(cpuprobe.LeafFeatures)
	}

	const aesNIBit = 1 << 25
	aesSupport := ecx&aesNIBit != 0

	plaintext := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	key := [16]byte{0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00}
	var out [16]byte

	aesFaulted := guardedAbortCall(func() {
		aesEncProbe(&plaintext[0], &key[0], &out[0])
	})

	isSpoofed := false
	if aesFaulted {
		if aesSupport {
			isSpoofed = true
		}
	} else if !aesSupport {
		isSpoofed = true
	}

	const cpuid1OSXSave = 1 << 27
	const cpuid1AVX = 1 << 28
	const cpuid7AVX2 = 1 << 5
	const xcr0AVXMask = 0x6

	avxAdv := ecx&cpuid1AVX != 0
	osxsaveAdv := ecx&cpuid1OSXSave != 0

	var b7 uint32
	if maxLeaf >= 7 {
		_, b7, _, _ = cpuprobe.CPUID(cpuprobe.LeafExtFeatures)
	}
	avx2Adv := b7&cpuid7AVX2 != 0

	if !isSpoofed && avxAdv && osxsaveAdv {
		if cpuHeuristicAVXCheck(xcr0AVXMask) {
			isSpoofed = true
		} else if avx2Adv && cpuHeuristicAVX2Check(xcr0AVXMask) {
			isSpoofed = true
		}
	}

	return isSpoofed
}

func cpuHeuristicAVXCheck(xcr0AVXMask uint32) bool {
	lo, _ := xgetbv0()
	if lo&xcr0AVXMask != xcr0AVXMask {
		return false
	}

	in0 := [8]float32{1, 2, 3, 4, 5, 6, 7, 8}
	in1 := [8]float32{16, 15, 14, 13, 12, 11, 10, 9}
	var out [8]float32

	faulted := guardedAbortCall(func() {
		avxAddProbe((*byte)(unsafe.Pointer(&in0[0])), (*byte)(unsafe.Pointer(&in1[0])), (*byte)(unsafe.Pointer(&out[0])))
	})
	if faulted {
		return true
	}
	return out[0] != 17.0
}

func cpuHeuristicAVX2Check(xcr0AVXMask uint32) bool {
	lo, _ := xgetbv0()
	if lo&xcr0AVXMask != xcr0AVXMask {
		return false
	}

	in0 := [8]uint32{1, 2, 3, 4, 5, 6, 7, 8}
	in1 := [8]uint32{16, 15, 14, 13, 12, 11, 10, 9}
	var out [8]uint32

	faulted := guardedAbortCall(func() {
		avx2AddProbe((*byte)(unsafe.Pointer(&in0[0])), (*byte)(unsafe.Pointer(&in1[0])), (*byte)(unsafe.Pointer(&out[0])))
	})
	if faulted {
		return true
	}
	return out[0] != 17
}
