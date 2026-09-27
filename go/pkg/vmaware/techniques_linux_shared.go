//go:build linux

package vmaware

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

// This file ports the Linux branch of vmaware.hpp's functions that are
// shared with other platforms via internal "#if VMAWARE_LINUX / #elif
// VMAWARE_WINDOWS" (or "#elif VMAWARE_APPLE") branches: azure(), firmware(),
// devices(), boot_logo(), disk() and thread_count(). Only the Linux side of
// each is ported here; the other platforms' branches are ported separately,
// under the same EnumFlag, in their own GOOS-tagged files.

func init() {
	RegisterTechnique(Azure, 30, azure)
	RegisterTechnique(Firmware, 100, firmware)
	RegisterTechnique(Devices, 95, devices)
	RegisterTechnique(BootLogo, 90, bootLogo)
	RegisterTechnique(Disk, 150, disk)
	RegisterTechnique(ThreadCount, 35, threadCount)
}

// ---------------------------------------------------------------------------
// azure() -- @implements VM::AZURE
// ---------------------------------------------------------------------------

// azure mirrors VM::azure's Linux branch.
//
// Upstream reads gethostname() into a fixed 16-byte, zero-initialized
// buffer and requires buf[13] == '\0': combined with the later
// starts_with("runnervm") + 5x is_alnum(buf[8..12]) checks, the only
// hostnames that can ever satisfy the whole function are exactly 13
// characters long ("runnervm" + 5 alphanumerics) -- any shorter or longer
// hostname fails one of those checks regardless. Go's os.Hostname() returns
// the hostname unbounded (no 16-byte truncation quirk to replicate), so the
// length check is written directly as len(hostname) == 13.
func azure() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	if len(hostname) != 13 {
		return false
	}
	if !strings.HasPrefix(hostname, "runnervm") {
		return false
	}

	isAlnum := func(c byte) bool {
		lower := c
		if c >= 'A' && c <= 'Z' {
			lower = c | 0x20
		}
		return (lower >= 'a' && lower <= 'z') || (c >= '0' && c <= '9')
	}

	if isAlnum(hostname[8]) && isAlnum(hostname[9]) && isAlnum(hostname[10]) &&
		isAlnum(hostname[11]) && isAlnum(hostname[12]) {
		return Add(BrandAzureHyperV)
	}
	return false
}

// ---------------------------------------------------------------------------
// firmware() -- @implements VM::FIRMWARE
// ---------------------------------------------------------------------------

// cStringFromBytes mirrors treating a fixed-size byte field as a
// NUL-terminated C string: truncate at the first 0x00 byte, if any.
func cStringFromBytes(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// firmwareTarget pairs one of the "targets" firmware-signature strings with
// its brand, mirroring the parallel "targets"/"brands_map" constexpr arrays
// in VM::firmware.
type firmwareTarget struct {
	pattern string
	brand   BrandEnum
}

var firmwareTargets = []firmwareTarget{
	{"Parallels Software", BrandParallels},
	{"Parallels(R)", BrandParallels},
	{"innotek", BrandVBOX},
	{"Oracle", BrandVBOX},
	{"VirtualBox", BrandVBOX},
	{"vbox", BrandVBOX},
	{"VBOX", BrandVBOX},
	{"VMware, Inc.", BrandVMWARE},
	{"VMware", BrandVMWARE},
	{"VMWARE", BrandVMWARE},
	{"VMW0003", BrandVMWARE},
	{"QEMU", BrandQEMU},
	{"pc-q35", BrandQEMU},
	{"Q35 +", BrandQEMU},
	{"FWCF", BrandQEMU},
	{"BOCHS", BrandBochs},
	{"ovmf", BrandNullBrand},
	{"edk ii unknown", BrandNullBrand},
	{"WAET", BrandNullBrand},
	{"S3 Corp.", BrandNullBrand},
	{"VS2005R2", BrandNullBrand},
	{"BXPC", BrandBochs},
	{"Xen", BrandXen},
}

// AML byte-pattern signatures used by the "1) AML Bytecode inspection"
// section of VM::firmware's scan_buffer. Each is transcribed verbatim from
// the corresponding constexpr u8 array in vmaware.hpp.
var (
	fwQemuDbgOpregion = []byte{0x5B, 0x80, 0x44, 0x42, 0x47, 0x5F, 0x01, 0x0B, 0x02, 0x04, 0x01}
	fwPnp0a06Eisa     = []byte{0x0C, 0x41, 0xD0, 0x0A, 0x06}
	fwUIDSignature    = []byte{0x08, 0x5F, 0x55, 0x49, 0x44}
	fwHpetSignature   = []byte{0x91, 0x93, 0x61, 0x00, 0x94, 0x61, 0x0C, 0x00, 0xE1, 0xF5, 0x05}
	fwSataAddrDummy   = []byte{0x08, 0x5F, 0x41, 0x44, 0x52, 0x0C, 0x02, 0x00, 0x1F, 0x00}
	fwS5Sig           = []byte{0x08, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00}
	// gpe_acpi0006 + 8, length 14: NameOp(_HID) + StringPrefix("ACPI0006").
	fwGpeACPI0006Wildcard = []byte{0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 'A', 'C', 'P', 'I', '0', '0', '0', '6'}
	fwMcfgDev             = []byte{'M', 'C', 'F', 'G', 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 'P', 'N', 'P', '0', 'C', '0', '1'}
	fwGsi16Descriptor     = []byte{0x89, 0x06, 0x00, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x79, 0x00}
	fwEmptyDisStub        = []byte{0x14, 0x06, 0x5F, 0x44, 0x49, 0x53, 0x00}
	fwEmptySrsStub        = []byte{0x14, 0x07, 0x5F, 0x53, 0x52, 0x53, 0x01}
	fwPciHostBridgeUUID   = []byte{0x5B, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D, 0xD7, 0x66}
	fwOscAndMaskSig       = []byte{0x7B, 0x43, 0x44, 0x57, 0x33, 0x0A, 0x1F, 0x60}
	fwEdsmDecl            = []byte{'E', 'D', 'S', 'M', 0x05}
	fwDeviceLabelingUUID  = []byte{0xD0, 0x37, 0xC9, 0xE5, 0x53, 0x35, 0x7A, 0x4D, 0x91, 0x17, 0xEA, 0x4D, 0x19, 0xC3, 0x43, 0x4D}
	fwPirqPrsIrqs         = []byte{0x89, 0x0E, 0x00, 0x09, 0x03, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x79, 0x00}
	fwPirqOpregion        = []byte{0x5B, 0x80, 'P', 'I', 'R', 'Q', 0x02, 0x0A, 0x60, 0x0A, 0x0C}
)

// firmwareGetPackageSize mirrors the "get_package_size" lambda used for the
// PRTP/PRTA routing-symmetry check: finds an occurrence of name preceded by
// NameOp (0x08) and followed by PackageOp (0x12), then returns the first
// byte in a small following window that looks like a realistic package
// element count (32..255).
func firmwareGetPackageSize(buffer []byte, name string) byte {
	if name == "" {
		return 0
	}
	nameBytes := []byte(name)
	searchFrom := 0

	for {
		idx := bytes.Index(buffer[searchFrom:], nameBytes)
		if idx < 0 {
			return 0
		}
		offset := searchFrom + idx

		if len(buffer)-offset >= 10 && offset >= 1 &&
			buffer[offset-1] == 0x08 && buffer[offset+4] == 0x12 {
			for k := 5; k < 12 && len(buffer)-offset > k; k++ {
				if v := buffer[offset+k]; v >= 32 {
					return v
				}
			}
		}

		searchFrom = offset + 1
		if searchFrom >= len(buffer) {
			return 0
		}
	}
}

// firmwareScanBuffer mirrors the "scan_buffer" lambda inside VM::firmware.
func firmwareScanBuffer(buffer []byte, isACPI bool) bool {
	if isACPI {
		// acpi_header is 36 bytes; too short to even hold a signature.
		if len(buffer) < 36 {
			return false
		}

		// 1) AML Bytecode inspection.
		if bytes.Contains(buffer, fwQemuDbgOpregion) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("DRAC")) && bytes.Contains(buffer, []byte("PNP0C01")) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("SMI resources")) || bytes.Contains(buffer, []byte("SMI interface")) {
			return Add(BrandQEMU)
		} else if idx := bytes.Index(buffer, fwPnp0a06Eisa); idx >= 0 {
			searchStart := 0
			if idx >= 64 {
				searchStart = idx - 64
			}
			searchEnd := len(buffer)
			if len(buffer)-idx >= 64 {
				searchEnd = idx + 64
			}
			if searchEnd >= 8 {
				for i := searchStart; i <= searchEnd-8; i++ {
					if bytes.Equal(buffer[i:i+5], fwUIDSignature) {
						if buffer[i+5] == 0x0D && buffer[i+6] == 'S' && buffer[i+7] == 'M' {
							return Add(BrandQEMU)
						}
					}
				}
			}
		}

		if bytes.Contains(buffer, []byte("CPU Hotplug resources")) {
			return Add(BrandQEMU)
		}
		if bytes.Contains(buffer, []byte("PCI Hotplug resources")) {
			return Add(BrandQEMU)
		}

		if prtp := firmwareGetPackageSize(buffer, "PRTP"); prtp != 0 {
			if prta := firmwareGetPackageSize(buffer, "PRTA"); prtp == prta {
				return Add(BrandQEMU)
			}
		}

		if bytes.Contains(buffer, []byte("HPET")) && bytes.Contains(buffer, fwHpetSignature) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("LNKE")) && bytes.Contains(buffer, []byte("LNKH")) &&
			bytes.Contains(buffer, []byte("GSIE")) && bytes.Contains(buffer, []byte("GSIH")) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("GPER")) || bytes.Contains(buffer, []byte("PHPR")) {
			if bytes.Contains(buffer, []byte("PNP0C01")) {
				return Add(BrandQEMU)
			}
		}

		if bytes.Contains(buffer, []byte("D0FA")) && bytes.Contains(buffer, fwSataAddrDummy) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("IQST")) && bytes.Contains(buffer, []byte("IQCR")) &&
			bytes.Contains(buffer, []byte("PRR0")) && bytes.Contains(buffer, []byte("PRRI")) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("MSFT0101")) || bytes.Contains(buffer, []byte("TPM 2.0 Device")) {
			if bytes.Contains(buffer, []byte("TPP2")) && bytes.Contains(buffer, []byte("TPP3")) && bytes.Contains(buffer, []byte("TPFN")) {
				return Add(BrandQEMU)
			}
		}

		if bytes.Contains(buffer, fwS5Sig) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, []byte("_GPE")) && bytes.Contains(buffer, []byte("ACPI0006")) {
			if bytes.Contains(buffer, fwGpeACPI0006Wildcard) {
				return Add(BrandQEMU)
			}
		}

		if bytes.Contains(buffer, []byte("MCFG")) && bytes.Contains(buffer, []byte("PNP0C01")) {
			if bytes.Contains(buffer, fwMcfgDev) {
				return Add(BrandQEMU)
			}
		}

		if bytes.Contains(buffer, fwGsi16Descriptor) && bytes.Contains(buffer, fwEmptyDisStub) && bytes.Contains(buffer, fwEmptySrsStub) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, fwPciHostBridgeUUID) && bytes.Contains(buffer, fwOscAndMaskSig) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, fwEdsmDecl) && bytes.Contains(buffer, fwDeviceLabelingUUID) {
			return Add(BrandQEMU)
		}

		if bytes.Contains(buffer, fwPirqPrsIrqs) && bytes.Contains(buffer, fwPirqOpregion) {
			return Add(BrandQEMU)
		}
	}

	// 2) standard VM-specific firmware signature scanning.
	for _, t := range firmwareTargets {
		if len(t.pattern) > len(buffer) {
			continue
		}
		if !bytes.Contains(buffer, []byte(t.pattern)) {
			continue
		}
		if t.pattern == "BXPC" {
			// Special handling for BOCHS: if BXPC is detected, check if
			// "BOCHS" is present too.
			if !bytes.Contains(buffer, []byte("BOCHS")) {
				return Add(BrandBochs)
			}
			continue
		}
		return Add(t.brand)
	}

	// 3) Known loader bypasses/patches.
	if len(buffer) >= 36 {
		oemID := cStringFromBytes(buffer[10:16])
		oemTableID := cStringFromBytes(buffer[16:24])
		if strings.Contains(oemID, "777777") {
			return Add(BrandVMWAREHard)
		}
		if strings.Contains(oemTableID, "777777") {
			return Add(BrandVMWAREHard)
		}
	}

	if isACPI {
		signature := buffer[0:4]

		// 4) FADT structure limits validation.
		if bytes.Equal(signature, []byte("FACP")) {
			headerLength := binary.LittleEndian.Uint32(buffer[4:8])
			if int(headerLength) > len(buffer) {
				return true
			}
			const fadtSize = 100 // sizeof(fadt_table), #pragma pack(push, 1)
			if len(buffer) >= fadtSize && int(headerLength) >= fadtSize {
				pLvl2Lat := binary.LittleEndian.Uint16(buffer[96:98])
				pLvl3Lat := binary.LittleEndian.Uint16(buffer[98:100])
				if pLvl2Lat == 0x0FFF || pLvl3Lat == 0x0FFF {
					return true
				}
			}
		}

		// 5) DMA Remapping table validation.
		if bytes.Equal(signature, []byte("DMAR")) {
			offset := 48
			for len(buffer) >= 4 && offset <= len(buffer)-4 {
				subtableType := binary.LittleEndian.Uint16(buffer[offset : offset+2])
				subtableLen := binary.LittleEndian.Uint16(buffer[offset+2 : offset+4])
				if subtableLen < 4 || int(subtableLen) > len(buffer)-offset {
					break
				}

				if subtableType == 0x0000 && subtableLen >= 16 {
					scopeOffset := offset + 16
					scopeEnd := offset + int(subtableLen)

					for scopeEnd >= 6 && scopeOffset <= scopeEnd-6 {
						scopeType := buffer[scopeOffset]
						scopeLen := int(buffer[scopeOffset+1])
						if scopeLen < 6 || scopeLen > scopeEnd-scopeOffset {
							break
						}

						busNum := buffer[scopeOffset+5]
						if scopeType == 0x03 && busNum == 0xFF {
							return Add(BrandQEMU)
						}
						if scopeType == 0x02 && scopeLen >= 8 && busNum == 0x00 {
							devNum := buffer[scopeOffset+6]
							funcNum := buffer[scopeOffset+7]
							if devNum == 0x02 && funcNum == 0x00 {
								return Add(BrandQEMU)
							}
						}

						scopeOffset += scopeLen
					}
				}

				offset += int(subtableLen)
			}
		}

		// 6) APIC/MADT table validation.
		if bytes.Equal(signature, []byte("APIC")) {
			offset := 44
			var qemuOverrideMask uint8

			for len(buffer) >= 2 && offset <= len(buffer)-2 {
				subtableType := buffer[offset]
				subtableLen := int(buffer[offset+1])
				if subtableLen < 2 || subtableLen > len(buffer)-offset {
					break
				}

				if subtableType == 0x02 && subtableLen == 10 {
					bus := buffer[offset+2]
					source := buffer[offset+3]
					gsi := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
					flags := binary.LittleEndian.Uint16(buffer[offset+8 : offset+10])

					var sourceMask uint8
					switch source {
					case 5:
						sourceMask = 1 << 0
					case 9:
						sourceMask = 1 << 1
					case 10:
						sourceMask = 1 << 2
					case 11:
						sourceMask = 1 << 3
					}

					polarity := flags & 0x0003
					triggerMode := flags & 0x000C
					validFlags := flags&0xFFF0 == 0
					activeHigh := polarity == 0 || polarity == 1
					levelTriggered := triggerMode == 0x000C

					if sourceMask != 0 && bus == 0 && gsi == uint32(source) &&
						validFlags && activeHigh && levelTriggered {
						qemuOverrideMask |= sourceMask
					}
				}

				offset += subtableLen
			}

			if qemuOverrideMask == 0x0F {
				return Add(BrandQEMU)
			}
		}
	}

	return false
}

// firmware mirrors VM::firmware's Linux branch (@implements VM::FIRMWARE).
func firmware() bool {
	const maxTableSize = 8 * 1024 * 1024
	const dir = "/sys/firmware/acpi/tables/"

	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(dir + entry.Name())
		if err != nil || len(data) == 0 || len(data) > maxTableSize {
			continue
		}

		if firmwareScanBuffer(data, true) {
			return true
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// devices() -- @implements VM::DEVICES
// ---------------------------------------------------------------------------

type pciDevice struct {
	vendorID uint16
	deviceID uint32
}

func parseHexField(s string) uint64 {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

// devicesLinuxList mirrors VM::devices' Linux branch: reads vendor/device ID
// pairs from every /sys/bus/pci/devices/*/{vendor,device} pair, defaulting
// to 0 (not skipping the entry) when a field fails to parse, exactly like
// the C++ side's "vf >> std::hex >> vid" leaving vid at its
// default-initialized value on extraction failure.
func devicesLinuxList() []pciDevice {
	var out []pciDevice

	entries, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		return out
	}

	for _, entry := range entries {
		base := "/sys/bus/pci/devices/" + entry.Name()
		if !pathExists(base+"/vendor") || !pathExists(base+"/device") {
			continue
		}
		vid := uint16(parseHexField(readFile(base + "/vendor")))
		did := uint32(parseHexField(readFile(base + "/device")))
		out = append(out, pciDevice{vendorID: vid, deviceID: did})
	}

	return out
}

// devices mirrors VM::devices (@implements VM::DEVICES).
func devices() bool {
	for _, d := range devicesLinuxList() {
		id64 := uint64(d.vendorID)<<32 | uint64(d.deviceID)
		id32 := uint32(d.vendorID)<<16 | d.deviceID

		switch id32 {
		// Red Hat + Virtio.
		case 0x1af40022, 0x1af41000, 0x1af41001, 0x1af41002,
			0x1af41003, 0x1af41004, 0x1af41005, 0x1af41009,
			0x1af41041, 0x1af41042, 0x1af41043, 0x1af41044,
			0x1af41045, 0x1af41048, 0x1af41049, 0x1af41050,
			0x1af41052, 0x1af41053, 0x1af4105a, 0x1af41100,
			0x1af41110, 0x1af41b36:
			return true

		// VMware.
		case 0x15ad0710, 0x15ad0720, 0x15ad0770, 0x15ad0774,
			0x15ad0778, 0x15ad0779, 0x15ad0790, 0x15ad07a0,
			0x15ad07b0, 0x15ad07c0, 0x15ad07e0, 0x15ad07f0,
			0x15ad0801, 0x15ad0820, 0x15ad1977, 0xfffe0710,
			0x0e0f0001, 0x0e0f0002, 0x0e0f0003, 0x0e0f0004,
			0x0e0f0005, 0x0e0f0006, 0x0e0f000a, 0x0e0f8001,
			0x0e0f8002, 0x0e0f8003, 0x0e0ff80a:
			return Add(BrandVMWARE)

		// Red Hat + QEMU.
		case 0x1b360001, 0x1b360002, 0x1b360003, 0x1b360004,
			0x1b360005, 0x1b360008, 0x1b360009, 0x1b36000b,
			0x1b36000c, 0x1b36000d, 0x1b360010, 0x1b360011,
			0x1b360013, 0x1b360100:
			return Add(BrandQEMU)

		// QEMU.
		case 0x06270001, 0x1d1d1f1f, 0x80865845, 0x1d6b0200:
			return Add(BrandQEMU)

		// VGPUs (NVIDIA + others).
		case 0x10de0fe7, 0x10de0ff7, 0x10de118d, 0x10de11b0, 0x1ec6020f:
			return true

		// VirtualBox.
		case 0x80ee0021, 0x80ee0022, 0x80eebeef, 0x80eecafe:
			return Add(BrandVBOX)

		// Parallels.
		case 0x1ab84000, 0x1ab84005, 0x1ab84006:
			return Add(BrandParallels)

		// Xen.
		case 0x5853c000, 0xfffd0101, 0x5853c147,
			0x5853c110, 0x5853c200, 0x58530001:
			return Add(BrandXen)

		// Connectix (VirtualPC).
		case 0x29556e61:
			return Add(BrandVPC)
		}

		// Devices with 32-bit device ids.
		switch id64 {
		case 0x0000000011061100, 0x000000001af41100, 0x000000001b361100,
			0x0000000010ec1100, 0x0000000010331100, 0x0000000080861100,
			0x0000000010131100, 0x00000000106b1100, 0x0000000010221100:
			return Add(BrandQEMU)

		case 0x0000000015ad0800: // Hypervisor ROM Interface.
			return Add(BrandVMWARE)
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// boot_logo() -- @implements VM::BOOT_LOGO
// ---------------------------------------------------------------------------

// bootLogo mirrors VM::boot_logo's Linux branch. Upstream gates the whole
// function behind "#if VMAWARE_X86_64"; Go has no compile-time GOARCH
// #ifdef inside a single function, so the same gate is applied at runtime.
// The CRC32-C (Castagnoli) computation matches util::hash::crc32c bit for
// bit (same table-driven reflected CRC, same 0xFFFFFFFF init/final XOR),
// so Go's standard hash/crc32 package is used instead of reimplementing the
// table generator.
func bootLogo() bool {
	if runtime.GOARCH != "amd64" {
		return false
	}

	const maxFileSize = 0x04000000 // 64 MB cap.
	data, err := os.ReadFile("/sys/firmware/acpi/bgrt/image")
	if err != nil || len(data) == 0 || len(data) > maxFileSize {
		return false
	}

	hash := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))

	switch hash {
	case 0x110350C5: // TianoCore EDK2.
		return Add(BrandQEMU)
	case 0x87c39681:
		return Add(BrandHyperV)
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// disk() -- @implements VM::DISK
// ---------------------------------------------------------------------------

func diskToLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c | 0x20
	}
	return c
}

func diskIsHex(c byte) bool {
	lower := diskToLower(c)
	return (c >= '0' && c <= '9') || (lower >= 'a' && lower <= 'f')
}

// diskIsQemuSerial mirrors the "is_qemu_serial" lambda in VM::disk: QEMU
// drives often start with "QM000" (case-insensitive on the first 2 chars).
func diskIsQemuSerial(s string) bool {
	if len(s) < 6 {
		return false
	}
	return diskToLower(s[0]) == 'q' && diskToLower(s[1]) == 'm' &&
		s[2] == '0' && s[3] == '0' && s[4] == '0' && s[5] == '0'
}

// diskIsVboxSerial mirrors the "is_vbox_serial" lambda in VM::disk: format
// "VB12345678-12345678" (19 chars).
func diskIsVboxSerial(s string) bool {
	if len(s) != 19 {
		return false
	}
	if diskToLower(s[0]) != 'v' || diskToLower(s[1]) != 'b' {
		return false
	}
	if s[10] != '-' {
		return false
	}
	for i := 2; i < 10; i++ {
		if !diskIsHex(s[i]) {
			return false
		}
	}
	for i := 11; i < 19; i++ {
		if !diskIsHex(s[i]) {
			return false
		}
	}
	return true
}

// disk mirrors VM::disk's Linux branch (@implements VM::DISK).
func disk() bool {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name[0] == '.' {
			continue
		}

		first := name[0]
		if first != 'n' && first != 's' && first != 'h' && first != 'v' {
			continue
		}
		if !(strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "sd") ||
			strings.HasPrefix(name, "sg") || strings.HasPrefix(name, "hd") ||
			strings.HasPrefix(name, "vd")) {
			continue
		}

		data, err := os.ReadFile("/sys/block/" + name + "/device/serial")
		if err != nil || len(data) == 0 {
			continue
		}

		serial := strings.TrimRight(string(data), "\n\r ")
		if diskIsQemuSerial(serial) || diskIsVboxSerial(serial) {
			return true
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// thread_count() -- @implements VM::THREAD_COUNT
// ---------------------------------------------------------------------------

// linuxThreadCountFetch mirrors VM::memo::thread_count::fetch(): a cached
// std::thread::hardware_concurrency(), defaulting to 1 if the platform
// can't report a count. runtime.NumCPU() is Go's equivalent of
// hardware_concurrency(). This is the exact same cache thread_mismatch()
// uses (see fetchThreadCount in techniques_cpu.go) — VM::memo::thread_count
// is one shared memoization slot upstream too, not one per technique.
func linuxThreadCountFetch() uint32 {
	return fetchThreadCount()
}

// threadCount mirrors VM::thread_count's "#if (VMAWARE_X86 &&
// !VMAWARE_APPLE)" branch, which on a non-Apple build reduces to just
// VMAWARE_X86 (ARM/other architectures fall through to "return false").
func threadCount() bool {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		return false
	}

	steps := cpuprobe.FetchSteppings()
	if cpuprobe.IsCeleron(steps) {
		return false
	}

	return linuxThreadCountFetch() <= 2
}
