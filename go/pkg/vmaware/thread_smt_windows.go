//go:build windows

package vmaware

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// groupAffinity mirrors the Win32 GROUP_AFFINITY struct (KAFFINITY Mask;
// WORD Group; WORD Reserved[3];). golang.org/x/sys/windows doesn't declare
// it, so it's reproduced here field-for-field; unsafe.Sizeof(groupAffinity{})
// below gives the same size the C compiler would (16 bytes on amd64/arm64,
// 12 on 386), since KAFFINITY is ULONG_PTR (== uintptr) and nothing here
// needs reordering or explicit padding on any of those targets.
type groupAffinity struct {
	Mask     uintptr
	Group    uint16
	Reserved [3]uint16
}

// relationProcessorCore mirrors LOGICAL_PROCESSOR_RELATIONSHIP::RelationProcessorCore.
const relationProcessorCore = 0

// processorRelationshipGroupMaskOffset mirrors
// offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor.GroupMask):
// DWORD Relationship (4) + DWORD Size (4) = 8 bytes before the union, then
// PROCESSOR_RELATIONSHIP's own BYTE Flags + BYTE EfficiencyClass +
// BYTE Reserved[20] + WORD GroupCount = 24 bytes before GroupMask. 8+24=32
// is already a multiple of 4 and 8, so this holds on both LLP64 (amd64,
// arm64) and ILP32 (386) targets -- no arch-specific padding to account for.
const processorRelationshipGroupMaskOffset = 32

var procGetLogicalProcessorInformationEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetLogicalProcessorInformationEx")

// isSMTActive mirrors the VMAWARE_WINDOWS branch of thread_mismatch()'s
// is_smt_active lambda (vmaware.hpp lines ~7053-7121): call
// GetLogicalProcessorInformationEx(RelationProcessorCore, ...) twice (once
// to size the buffer, once to fill it -- looping to tolerate CPU hot-plug
// growing the required size between the two calls), then walk the returned
// SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX records byte-by-byte exactly like
// the C++ source does (it reinterpret_casts into a raw unsigned char*
// buffer rather than indexing a typed array), reporting true the moment any
// RelationProcessorCore record's GroupMask carries more than one logical
// processor bit.
func isSMTActive() bool {
	var length uint32

	r1, _, callErr := procGetLogicalProcessorInformationEx.Call(
		uintptr(relationProcessorCore),
		0,
		uintptr(unsafe.Pointer(&length)),
	)
	if r1 != 0 || callErr != windows.ERROR_INSUFFICIENT_BUFFER {
		return false
	}

	var buf []byte
	for {
		buf = make([]byte, length)

		r1, _, callErr = procGetLogicalProcessorInformationEx.Call(
			uintptr(relationProcessorCore),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&length)),
		)
		if r1 != 0 {
			break
		}

		if callErr != windows.ERROR_INSUFFICIENT_BUFFER {
			return false
		}
	}

	groupAffinitySize := uint32(unsafe.Sizeof(groupAffinity{}))
	bufLen := uint32(len(buf))

	result := false
	var offset uint32
	for offset < bufLen {
		if bufLen-offset < 8 { // sizeof(DWORD)*2
			break
		}

		relationship := *(*uint32)(unsafe.Pointer(&buf[offset]))
		size := *(*uint32)(unsafe.Pointer(&buf[offset+4]))

		if size == 0 || uint64(offset)+uint64(size) > uint64(bufLen) {
			break
		}

		if relationship == relationProcessorCore {
			if size < processorRelationshipGroupMaskOffset {
				break
			}

			groupCount := *(*uint16)(unsafe.Pointer(&buf[offset+30]))
			minSize := uint64(processorRelationshipGroupMaskOffset) + uint64(groupCount)*uint64(groupAffinitySize)
			if uint64(size) < minSize {
				break
			}

			var logicals int32
			for i := uint16(0); i < groupCount; i++ {
				maskOffset := offset + processorRelationshipGroupMaskOffset + uint32(i)*groupAffinitySize
				mask := *(*uintptr)(unsafe.Pointer(&buf[maskOffset]))
				logicals += popcount(uint64(mask))
			}

			if logicals > 1 {
				result = true
				break
			}
		}

		offset += size
	}

	return result
}
