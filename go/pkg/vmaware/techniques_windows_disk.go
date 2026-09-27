//go:build windows

package vmaware

// Port of the Windows branch of disk() (@implements VM::DISK, vmaware.hpp
// ~10924-11478): opens every \\.\PhysicalDriveN, queries its
// STORAGE_DEVICE_DESCRIPTOR for a QEMU/VirtualBox-shaped serial number, and
// (for NVMe/unknown-bus drives without a matching serial) probes a couple
// of NVMe Identify-Controller/Identify-Namespace heuristics via
// IOCTL_STORAGE_QUERY_PROPERTY's protocol-specific query.
//
// Deliberate deviation from upstream: upstream drives this entirely through
// the native NT API (NtOpenFile/NtDeviceIoControlFile on \??\PhysicalDriveN)
// to avoid a Win32 CreateFile/DeviceIoControl round trip. This port uses the
// ordinary Win32 CreateFileW + DeviceIoControl path instead, which reaches
// the exact same storage miniport IOCTL handler and STORAGE_* structures,
// because hand-rolling the native UNICODE_STRING/OBJECT_ATTRIBUTES call
// convention for a technique that can't be tested here is a needless extra
// source of error; every byte-level parsing rule below (descriptor layout,
// serial offset, NVMe OACS/LBA-format checks) is otherwise unchanged.

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(Disk, 150, diskTechnique)
}

const ioctlStorageQueryProperty = 0x2D1400

const (
	storagePropertyStorageDevice           = 0
	storagePropertyAdapterProtocolSpecific = 49
	storageQueryTypeStandard               = 0
	storageProtocolTypeNvme                = 3
)

func isQemuSerial(s string) bool {
	if len(s) < 6 {
		return false
	}
	return (s[0]|0x20) == 'q' && (s[1]|0x20) == 'm' && s[2] == '0' && s[3] == '0' && s[4] == '0' && s[5] == '0'
}

func isVboxSerial(s string) bool {
	if len(s) != 19 {
		return false
	}
	if (s[0]|0x20) != 'v' || (s[1]|0x20) != 'b' {
		return false
	}
	if s[10] != '-' {
		return false
	}
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c|0x20 >= 'a' && c|0x20 <= 'f')
	}
	for i := 2; i < 10; i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	for i := 11; i < 19; i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// storageDeviceDescriptorHeader is the fixed-size prefix of
// STORAGE_DEVICE_DESCRIPTOR.
type storageDeviceDescriptorHeader struct {
	Version             uint32
	Size                uint32
	DeviceType          byte
	DeviceTypeModifier  byte
	RemovableMedia      byte
	CommandQueueing     byte
	VendorIDOffset      uint32
	ProductIDOffset     uint32
	ProductRevisionOff  uint32
	SerialNumberOffset  uint32
	BusType             uint32
	RawPropertiesLength uint32
}

func diskTechnique() bool {
	const maxPhysicalDrives = 256
	const maxConsecutiveMisses = 4
	successfulOpens := 0
	consecutiveMisses := 0

	for drive := 0; drive < maxPhysicalDrives; drive++ {
		path := `\\.\PhysicalDrive` + itoaUint(drive)
		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			continue
		}

		h, err := windows.CreateFile(
			pathPtr,
			0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil || h == windows.InvalidHandle {
			consecutiveMisses++
			if consecutiveMisses >= maxConsecutiveMisses {
				break
			}
			continue
		}
		consecutiveMisses = 0
		successfulOpens++

		serialDetected, busType := diskQuerySerial(h)
		if serialDetected {
			windows.CloseHandle(h)
			return true
		}

		const busTypeNVMe = 17
		const busTypeUnknown = 0
		if busType == busTypeNVMe || busType == busTypeUnknown {
			if diskCheckNVMeHeuristics(h) {
				windows.CloseHandle(h)
				return true
			}
		}

		windows.CloseHandle(h)
	}

	if successfulOpens == 0 {
		return true
	}
	return false
}

func itoaUint(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// diskQuerySerial issues IOCTL_STORAGE_QUERY_PROPERTY/StorageDeviceProperty
// and checks the returned serial number against the QEMU/VBox patterns.
func diskQuerySerial(h windows.Handle) (serialDetected bool, busType uint32) {
	query := make([]byte, 8)
	binary.LittleEndian.PutUint32(query[0:4], storagePropertyStorageDevice)
	binary.LittleEndian.PutUint32(query[4:8], storageQueryTypeStandard)

	const maxDescriptorSize = 64 * 1024
	buf := make([]byte, 1024)
	var bytesReturned uint32
	err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &query[0], uint32(len(query)), &buf[0], uint32(len(buf)), &bytesReturned, nil)

	if err != nil || bytesReturned < uint32(unsafe.Sizeof(storageDeviceDescriptorHeader{})) {
		// Retry with a bigger buffer sized from the descriptor's own
		// reported Size, mirroring upstream's realloc-on-overflow path.
		if bytesReturned < 8 {
			return false, 0
		}
		reportedSize := binary.LittleEndian.Uint32(buf[4:8])
		if reportedSize < uint32(unsafe.Sizeof(storageDeviceDescriptorHeader{})) || reportedSize > maxDescriptorSize {
			return false, 0
		}
		buf = make([]byte, reportedSize)
		err = windows.DeviceIoControl(h, ioctlStorageQueryProperty, &query[0], uint32(len(query)), &buf[0], uint32(len(buf)), &bytesReturned, nil)
		if err != nil || bytesReturned < uint32(unsafe.Sizeof(storageDeviceDescriptorHeader{})) {
			return false, 0
		}
	}

	desc := (*storageDeviceDescriptorHeader)(unsafe.Pointer(&buf[0]))
	activeSize := desc.Size
	if activeSize > bytesReturned {
		activeSize = bytesReturned
	}
	if activeSize > uint32(len(buf)) {
		activeSize = uint32(len(buf))
	}

	busType = desc.BusType

	serialOffset := desc.SerialNumberOffset
	if serialOffset >= uint32(unsafe.Sizeof(storageDeviceDescriptorHeader{})) && serialOffset < activeSize {
		maxAvail := activeSize - serialOffset
		serialBytes := buf[serialOffset : serialOffset+maxAvail]
		end := indexByteOrLen(serialBytes, 0)
		serial := string(serialBytes[:end])
		if isQemuSerial(serial) || isVboxSerial(serial) {
			serialDetected = true
		}
	}

	return serialDetected, busType
}

// diskCheckNVMeHeuristics mirrors disk()'s check_nvme_heuristics lambda.
func diskCheckNVMeHeuristics(h windows.Handle) bool {
	identifyCtrl, ok := diskQueryNVMeProtocol(h, 1, 0x01, 0, 4096)
	if ok {
		if len(identifyCtrl) >= 258 {
			oacs := binary.LittleEndian.Uint16(identifyCtrl[256:258])
			supportsVirtualizationMgmt := oacs&(1<<8) != 0
			supportsNamespaceMgmt := oacs&(1<<3) != 0
			lacksSelfTest := oacs&(1<<4) == 0
			if supportsVirtualizationMgmt && supportsNamespaceMgmt && lacksSelfTest {
				return true
			}
		}
	}

	identifyNS, ok := diskQueryNVMeProtocol(h, 1, 0x00, 1, 4096)
	if ok && len(identifyNS) >= 4096 {
		nlbaf := identifyNS[25]
		if nlbaf == 7 {
			hasMetadataOption := false
			for i := 0; i < 8; i++ {
				entryOffset := 128 + i*4
				ms := binary.LittleEndian.Uint16(identifyNS[entryOffset : entryOffset+2])
				if ms != 0 {
					hasMetadataOption = true
					break
				}
			}
			if hasMetadataOption {
				return Add(BrandQEMU)
			}
		}
	}

	return false
}

// diskQueryNVMeProtocol issues IOCTL_STORAGE_QUERY_PROPERTY with
// StorageAdapterProtocolSpecificProperty / ProtocolTypeNvme, mirroring
// disk()'s query_protocol lambda.
func diskQueryNVMeProtocol(h windows.Handle, dataType, reqVal, reqSubVal, outSize uint32) ([]byte, bool) {
	const headerSize = 48 // sizeof(STORAGE_PROPERTY_QUERY header) + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
	const maxDescriptorSize = 64 * 1024
	if outSize == 0 || outSize > maxDescriptorSize-headerSize {
		return nil, false
	}

	total := headerSize + outSize
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], storagePropertyAdapterProtocolSpecific)
	binary.LittleEndian.PutUint32(buf[4:8], storageQueryTypeStandard)
	binary.LittleEndian.PutUint32(buf[8:12], storageProtocolTypeNvme)
	binary.LittleEndian.PutUint32(buf[12:16], dataType)
	binary.LittleEndian.PutUint32(buf[16:20], reqVal)
	binary.LittleEndian.PutUint32(buf[20:24], reqSubVal)
	binary.LittleEndian.PutUint32(buf[24:28], 40) // ProtocolDataOffset relative to protocol_data start
	binary.LittleEndian.PutUint32(buf[28:32], outSize)

	var bytesReturned uint32
	err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &bytesReturned, nil)
	if err != nil {
		return nil, false
	}

	validLen := bytesReturned
	if validLen > uint32(len(buf)) {
		validLen = uint32(len(buf))
	}
	if validLen < headerSize {
		return nil, false
	}

	dataOffset := binary.LittleEndian.Uint32(buf[24:28])
	reportedLen := binary.LittleEndian.Uint32(buf[28:32])
	if reportedLen < outSize {
		return nil, false
	}

	var payloadOffset uint32
	switch {
	case dataOffset >= headerSize:
		payloadOffset = dataOffset
	case dataOffset >= 40: // sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
		payloadOffset = 8 + dataOffset
	}

	if payloadOffset < headerSize || payloadOffset > validLen || outSize > validLen-payloadOffset {
		return nil, false
	}

	out := make([]byte, outSize)
	copy(out, buf[payloadOffset:payloadOffset+outSize])
	return out, true
}
