//go:build windows

package vmaware

// Port of vcpu_scheduling() (@implements VM::VCPU_SCHEDULING, vmaware.hpp
// ~16833-16957): takes two snapshots of the system's physical-core topology
// (via GetLogicalProcessorInformationEx(RelationProcessorCore, ...), 25ms
// apart) and flags any change in core count, group/affinity-mask mapping,
// or P-core/E-core identity, which a real, unpinned-vCPU-migrating
// hypervisor can produce but bare-metal topology never does on its own.
//
// Reuses procGetLogicalProcessorInformationEx, groupAffinity,
// relationProcessorCore and processorRelationshipGroupMaskOffset from
// thread_smt_windows.go (another Windows technique's helper for the same
// Win32 API and struct layout).

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(VCPUScheduling, 100, vcpuSchedulingTechnique)
}

type physicalProcessorEntry struct {
	GroupID         uint16
	Mask            uintptr
	EfficiencyClass byte
	IsPCore         bool
}

// processorRelationshipEfficiencyClassOffset mirrors
// offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor.EfficiencyClass):
// DWORD Relationship(4) + DWORD Size(4) + BYTE Flags(1) = 9.
const processorRelationshipEfficiencyClassOffset = 9

func vcpuSchedulingSnapshot() ([]physicalProcessorEntry, bool) {
	if procGetLogicalProcessorInformationEx == nil {
		return nil, false
	}

	var bufferSize uint32
	r1, _, callErr := procGetLogicalProcessorInformationEx.Call(uintptr(relationProcessorCore), 0, uintptr(unsafe.Pointer(&bufferSize)))
	if r1 == 0 && callErr != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, false
	}
	if bufferSize == 0 {
		return nil, false
	}

	buf := make([]byte, bufferSize)
	r1, _, _ = procGetLogicalProcessorInformationEx.Call(uintptr(relationProcessorCore), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufferSize)))
	if r1 == 0 {
		return nil, false
	}

	const minHeaderSize = 8 + 4 // LOGICAL_PROCESSOR_RELATIONSHIP header (Relationship+Size) + at least a DWORD
	var entries []physicalProcessorEntry
	offset := uint32(0)

	for offset+minHeaderSize <= bufferSize {
		relationship := le32(buf[offset : offset+4])
		size := le32(buf[offset+4 : offset+8])
		if size < minHeaderSize || size > bufferSize-offset {
			break
		}

		if relationship == relationProcessorCore {
			const minProcRelSize = processorRelationshipGroupMaskOffset
			if size < minProcRelSize {
				offset += size
				continue
			}

			effClass := buf[offset+processorRelationshipEfficiencyClassOffset]
			isPCore := effClass > 0
			groupCount := le16(buf[offset+30 : offset+32])

			for g := uint16(0); g < groupCount; g++ {
				maskOffset := offset + processorRelationshipGroupMaskOffset + uint32(g)*uint32(unsafe.Sizeof(groupAffinity{}))
				if maskOffset+uint32(unsafe.Sizeof(groupAffinity{})) > offset+size {
					break
				}
				ga := (*groupAffinity)(unsafe.Pointer(&buf[maskOffset]))

				entries = append(entries, physicalProcessorEntry{
					GroupID:         ga.Group,
					Mask:            ga.Mask,
					EfficiencyClass: effClass,
					IsPCore:         isPCore,
				})
			}
		}

		offset += size
	}

	if len(entries) == 0 {
		return nil, false
	}
	return entries, true
}

func vcpuSchedulingTechnique() bool {
	const runCount = 2
	runs := make([][]physicalProcessorEntry, runCount)

	for r := 0; r < runCount; r++ {
		entries, ok := vcpuSchedulingSnapshot()
		if !ok {
			return false
		}
		runs[r] = entries

		if r+1 < runCount {
			time.Sleep(25 * time.Millisecond)
		}
	}

	if len(runs[0]) != len(runs[1]) {
		return true
	}

	for i := range runs[0] {
		a, b := runs[0][i], runs[1][i]
		if a.GroupID != b.GroupID || a.Mask != b.Mask || a.EfficiencyClass != b.EfficiencyClass || a.IsPCore != b.IsPCore {
			return true
		}
	}

	return false
}
