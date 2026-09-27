//go:build windows

package vmaware

// Port of the Windows branch of firmware() (@implements VM::FIRMWARE,
// vmaware.hpp ~9582-10450): scans every ACPI table (via
// EnumSystemFirmwareTables/GetSystemFirmwareTable) plus SMBIOS/FIRM tables
// for VM-specific AML bytecode signatures, known VM vendor strings, a
// VMwareHardenedLoader OEM ID/table ID patch marker, and FADT/DMAR/APIC
// structural VM tells.

import (
	"bytes"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(Firmware, 100, firmwareTechnique)
}

var (
	procEnumSystemFirmwareTables = procOrNil(modKernel32, "EnumSystemFirmwareTables")
	procGetSystemFirmwareTable   = procOrNil(modKernel32, "GetSystemFirmwareTable")
)

// firmwareTargets/firmwareBrandsMap mirror firmware()'s `targets`/`brands_map`.
var firmwareTargets = []string{
	"Parallels Software", "Parallels(R)",
	"innotek", "Oracle", "VirtualBox", "vbox", "VBOX",
	"VMware, Inc.", "VMware", "VMWARE", "VMW0003",
	"QEMU", "pc-q35", "Q35 +", "FWCF", "BOCHS",
	"ovmf", "edk ii unknown", "WAET", "S3 Corp.", "VS2005R2",
	"BXPC", "Xen",
}

var firmwareBrandsMap = []BrandEnum{
	BrandParallels, BrandParallels,
	BrandVBOX, BrandVBOX, BrandVBOX, BrandVBOX, BrandVBOX,
	BrandVMWARE, BrandVMWARE, BrandVMWARE, BrandVMWARE,
	BrandQEMU, BrandQEMU, BrandQEMU, BrandQEMU, BrandBochs,
	BrandNullBrand, BrandNullBrand, BrandNullBrand, BrandNullBrand, BrandNullBrand,
	BrandBochs, BrandXen,
}

func findPattern(buffer, pattern []byte) bool {
	if len(pattern) == 0 || len(pattern) > len(buffer) {
		return false
	}
	return bytes.Contains(buffer, pattern)
}

func findPatternStr(buffer []byte, pattern string) bool {
	return findPattern(buffer, []byte(pattern))
}

// acpiHeaderView reads the fixed portion of an ACPI table header (36 bytes:
// signature[4] + length(4) + revision(1) + checksum(1) + oem_id[6] +
// oem_table_id[8] + oem_revision(4) + asl_compiler_id[4] +
// asl_compiler_revision(4)).
type acpiHeaderView struct {
	Signature [4]byte
	Length    uint32
}

func readACPIHeader(buf []byte) (acpiHeaderView, bool) {
	if len(buf) < 36 {
		return acpiHeaderView{}, false
	}
	var h acpiHeaderView
	copy(h.Signature[:], buf[0:4])
	h.Length = le32(buf[4:8])
	return h, true
}

// scanFirmwareBuffer mirrors firmware()'s scan_buffer lambda.
func scanFirmwareBuffer(buffer []byte, isACPI bool) bool {
	if len(buffer) == 0 {
		return false
	}

	header, haveHeader := acpiHeaderView{}, false
	if isACPI {
		header, haveHeader = readACPIHeader(buffer)
	}

	if isACPI && haveHeader {
		// 1) AML bytecode inspection.
		qemuDbgOpregion := []byte{0x5B, 0x80, 0x44, 0x42, 0x47, 0x5F, 0x01, 0x0B, 0x02, 0x04, 0x01}
		if findPattern(buffer, qemuDbgOpregion) {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "DBUG") && findPatternStr(buffer, "DBGB") {
			isAcerAspire := false
			if man, mod, ok := getManufacturerAndModel(); ok {
				if strings.Contains(strings.ToLower(man), "acer") && strings.Contains(strings.ToLower(mod), "aspire") {
					isAcerAspire = true
				}
			}
			if !isAcerAspire {
				return Add(BrandQEMU)
			}
		}

		if findPatternStr(buffer, "DRAC") && findPatternStr(buffer, "PNP0C01") {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "SMI resources") || findPatternStr(buffer, "SMI interface") {
			return Add(BrandQEMU)
		} else {
			pnp0a06EISA := []byte{0x0C, 0x41, 0xD0, 0x0A, 0x06}
			uidSignature := []byte{0x08, 0x5F, 0x55, 0x49, 0x44}

			if idx := bytes.Index(buffer, pnp0a06EISA); idx >= 0 {
				searchStart := 0
				if idx >= 64 {
					searchStart = idx - 64
				}
				searchEnd := len(buffer)
				if len(buffer)-idx >= 64 {
					searchEnd = idx + 64
				}
				for i := searchStart; searchEnd >= 8 && i <= searchEnd-8; i++ {
					if bytes.Equal(buffer[i:i+5], uidSignature) {
						if buffer[i+5] == 0x0D && buffer[i+6] == 'S' && buffer[i+7] == 'M' {
							return Add(BrandQEMU)
						}
					}
				}
			}
		}

		if findPatternStr(buffer, "CPU Hotplug resources") {
			return Add(BrandQEMU)
		}
		if findPatternStr(buffer, "PCI Hotplug resources") {
			return Add(BrandQEMU)
		}

		{
			getPackageSize := func(name string) byte {
				nb := []byte(name)
				pos := 0
				for {
					idx := bytes.IndexByte(buffer[pos:], nb[0])
					if idx < 0 {
						return 0
					}
					offset := pos + idx
					if len(buffer)-offset >= 10 && bytes.Equal(buffer[offset:offset+4], nb) {
						if offset >= 1 && buffer[offset-1] == 0x08 && buffer[offset+4] == 0x12 {
							for k := 5; k < 12 && len(buffer)-offset > k; k++ {
								if buffer[offset+k] >= 32 {
									return buffer[offset+k]
								}
							}
						}
					}
					pos = offset + 1
					if pos >= len(buffer) {
						return 0
					}
				}
			}

			prtpSize := getPackageSize("PRTP")
			prtaSize := getPackageSize("PRTA")
			if prtpSize != 0 && prtpSize == prtaSize {
				return Add(BrandQEMU)
			}
		}

		if findPatternStr(buffer, "HPET") {
			qemuHpetSignature := []byte{0x91, 0x93, 0x61, 0x00, 0x94, 0x61, 0x0C, 0x00, 0xE1, 0xF5, 0x05}
			if findPattern(buffer, qemuHpetSignature) {
				return Add(BrandQEMU)
			}
		}

		if findPatternStr(buffer, "LNKE") && findPatternStr(buffer, "LNKH") && findPatternStr(buffer, "GSIE") && findPatternStr(buffer, "GSIH") {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "GPER") || findPatternStr(buffer, "PHPR") {
			if findPatternStr(buffer, "PNP0A06") {
				return Add(BrandQEMU)
			}
		}

		sataAddrDummy := []byte{0x08, 0x5F, 0x41, 0x44, 0x52, 0x0C, 0x02, 0x00, 0x1F, 0x00}
		if findPatternStr(buffer, "D0FA") && findPattern(buffer, sataAddrDummy) {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "IQST") && findPatternStr(buffer, "IQCR") && findPatternStr(buffer, "PRR0") && findPatternStr(buffer, "PRRI") {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "MSFT0101") || findPatternStr(buffer, "TPM 2.0 Device") {
			if findPatternStr(buffer, "TPP2") && findPatternStr(buffer, "TPP3") && findPatternStr(buffer, "TPFN") {
				return Add(BrandQEMU)
			}
		}

		qemuS5Sig := []byte{0x08, 0x5F, 0x53, 0x35, 0x5F, 0x12, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00}
		if findPattern(buffer, qemuS5Sig) {
			return Add(BrandQEMU)
		}

		if findPatternStr(buffer, "_GPE") && findPatternStr(buffer, "ACPI0006") {
			gpeACPI0006Wildcard := []byte{0x5C, 0x2E, 0x5F, 0x47, 0x50, 0x45, 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 'A', 'C', 'P', 'I', '0', '0', '0', '6'}
			if findPattern(buffer, gpeACPI0006Wildcard) {
				return Add(BrandQEMU)
			}
		}

		if findPatternStr(buffer, "MCFG") && findPatternStr(buffer, "PNP0C01") {
			mcfgDev := []byte{'M', 'C', 'F', 'G', 0x08, 0x5F, 0x48, 0x49, 0x44, 0x0D, 'P', 'N', 'P', '0', 'C', '0', '1'}
			if findPattern(buffer, mcfgDev) {
				return Add(BrandQEMU)
			}
		}

		{
			gsi16Descriptor := []byte{0x89, 0x06, 0x00, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x79, 0x00}
			emptyDisStub := []byte{0x14, 0x06, 0x5F, 0x44, 0x49, 0x53, 0x00}
			emptySrsStub := []byte{0x14, 0x07, 0x5F, 0x53, 0x52, 0x53, 0x01}
			if findPattern(buffer, gsi16Descriptor) && findPattern(buffer, emptyDisStub) && findPattern(buffer, emptySrsStub) {
				return Add(BrandQEMU)
			}
		}

		{
			pciHostBridgeUUID := []byte{0x5B, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D, 0xD7, 0x66}
			oscAndMaskSig := []byte{0x7B, 0x43, 0x44, 0x57, 0x33, 0x0A, 0x1F, 0x60}
			if findPattern(buffer, pciHostBridgeUUID) && findPattern(buffer, oscAndMaskSig) {
				return Add(BrandQEMU)
			}
		}

		{
			edsmDecl := []byte{'E', 'D', 'S', 'M', 0x05}
			deviceLabelingUUID := []byte{0xD0, 0x37, 0xC9, 0xE5, 0x53, 0x35, 0x7A, 0x4D, 0x91, 0x17, 0xEA, 0x4D, 0x19, 0xC3, 0x43, 0x4D}
			if findPattern(buffer, edsmDecl) && findPattern(buffer, deviceLabelingUUID) {
				return Add(BrandQEMU)
			}
		}

		{
			pirqPRSIrqs := []byte{0x89, 0x0E, 0x00, 0x09, 0x03, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x79, 0x00}
			pirqOpregion := []byte{0x5B, 0x80, 'P', 'I', 'R', 'Q', 0x02, 0x0A, 0x60, 0x0A, 0x0C}
			if findPattern(buffer, pirqPRSIrqs) && findPattern(buffer, pirqOpregion) {
				return Add(BrandQEMU)
			}
		}
	}

	// 2) standard VM-specific firmware signature scanning.
	for i, pattern := range firmwareTargets {
		if !findPatternStr(buffer, pattern) {
			continue
		}
		if pattern == "BXPC" {
			if !findPatternStr(buffer, "BOCHS") {
				return Add(BrandBochs)
			}
			continue
		}
		return Add(firmwareBrandsMap[i])
	}

	// 3) known loader bypasses/patches (VMwareHardenedLoader).
	if len(buffer) >= 36 {
		oemID := string(buffer[10:16])
		oemTableID := string(buffer[16:24])
		if strings.Contains(oemID, "777777") || strings.Contains(oemTableID, "777777") {
			return Add(BrandVMWAREHard)
		}
	}

	if isACPI && haveHeader {
		if bytes.Equal(header.Signature[:], []byte("FACP")) {
			if header.Length > uint32(len(buffer)) {
				return true
			}
			const fadtTableSize = 76 // sizeof(fadt_table) up through p_lvl3_lat
			if len(buffer) < fadtTableSize || header.Length < fadtTableSize {
				return false
			}
			pLvl2Lat := le16(buffer[72:74])
			pLvl3Lat := le16(buffer[74:76])
			if pLvl2Lat == 0x0FFF || pLvl3Lat == 0x0FFF {
				return true
			}
		}

		if bytes.Equal(header.Signature[:], []byte("DMAR")) {
			if scanDMARTable(buffer) {
				return true // scanDMARTable already called Add internally
			}
		}

		if bytes.Equal(header.Signature[:], []byte("APIC")) {
			if scanMADTTable(buffer) {
				return true
			}
		}
	}

	return false
}

func scanDMARTable(buffer []byte) bool {
	offset := 48
	for len(buffer) >= 4 && offset <= len(buffer)-4 {
		subtableType := le16(buffer[offset : offset+2])
		subtableLen := le16(buffer[offset+2 : offset+4])

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
	return false
}

func scanMADTTable(buffer []byte) bool {
	offset := 44
	var qemuOverrideMask byte

	for len(buffer) >= 2 && offset <= len(buffer)-2 {
		subtableType := buffer[offset]
		subtableLen := int(buffer[offset+1])

		if subtableLen < 2 || subtableLen > len(buffer)-offset {
			break
		}

		if subtableType == 0x02 && subtableLen == 10 {
			bus := buffer[offset+2]
			source := buffer[offset+3]
			globalSystemInterrupt := le32(buffer[offset+4 : offset+8])
			flags := le16(buffer[offset+8 : offset+10])

			var sourceMask byte
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

			if sourceMask != 0 && bus == 0 && globalSystemInterrupt == uint32(source) && validFlags && activeHigh && levelTriggered {
				qemuOverrideMask |= sourceMask
			}
		}
		offset += subtableLen
	}

	if qemuOverrideMask == 0x0F {
		return Add(BrandQEMU)
	}
	return false
}

func enumFirmwareTables(signature uint32) []uint32 {
	if procEnumSystemFirmwareTables == nil {
		return nil
	}
	size, _, _ := procEnumSystemFirmwareTables.Call(uintptr(signature), 0, 0)
	if size == 0 || size%4 != 0 {
		return nil
	}
	count := size / 4
	tables := make([]uint32, count)
	r1, _, _ := procEnumSystemFirmwareTables.Call(uintptr(signature), uintptr(unsafe.Pointer(&tables[0])), size)
	if r1 != size {
		return nil
	}
	return tables
}

func getFirmwareTable(provider, tableID uint32) ([]byte, bool) {
	if procGetSystemFirmwareTable == nil {
		return nil, false
	}
	sz, _, _ := procGetSystemFirmwareTable.Call(uintptr(provider), uintptr(tableID), 0, 0)
	if sz == 0 {
		return nil, false
	}
	buf := make([]byte, sz)
	r1, _, _ := procGetSystemFirmwareTable.Call(uintptr(provider), uintptr(tableID), uintptr(unsafe.Pointer(&buf[0])), sz)
	if r1 != sz {
		return nil, false
	}
	return buf, true
}

func fourCC(s string) uint32 {
	// Matches the C++ side's use of the MSVC/GCC multi-character constant
	// 'ACPI' etc: the bytes of the literal packed big-endian into a DWORD.
	b := []byte(s)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func swap32(v uint32) uint32 {
	return (v>>24)&0xFF | (v>>8)&0xFF00 | (v<<8)&0xFF0000 | (v << 24)
}

func firmwareTechnique() bool {
	const acpiSignature = 0x41435049 // 'ACPI' as a big-endian-packed DWORD, matches fourCC("ACPI")
	_ = fourCC

	tables := enumFirmwareTables(acpiSignature)
	if tables == nil {
		return false
	}

	// DSDT special fetch.
	dsdtSwapped := swap32(0x44534454) // 'DSDT'
	if buf, ok := getFirmwareTable(acpiSignature, dsdtSwapped); ok {
		if scanFirmwareBuffer(buf, true) {
			return true
		}
	}

	for _, tableID := range tables {
		if buf, ok := getFirmwareTable(acpiSignature, tableID); ok {
			if scanFirmwareBuffer(buf, true) {
				return true
			}
		}
	}

	smbProviders := []uint32{0x46495254 /* not used */, 0}
	_ = smbProviders
	for _, prov := range []uint32{fourCCLiteral('F', 'I', 'R', 'M'), fourCCLiteral('R', 'S', 'M', 'B')} {
		provTables := enumFirmwareTables(prov)
		for _, tableID := range provTables {
			if buf, ok := getFirmwareTable(prov, tableID); ok {
				if scanFirmwareBuffer(buf, false) {
					return true
				}
			}
		}
	}

	return false
}

// fourCCLiteral packs 4 ASCII bytes into a DWORD exactly like MSVC/GCC's
// multi-character constant 'XXXX' does: the first character ends up in the
// least significant byte.
func fourCCLiteral(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

var _ = windows.STATUS_SUCCESS
