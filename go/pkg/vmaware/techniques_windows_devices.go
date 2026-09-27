//go:build windows

package vmaware

// Port of the Windows branch of devices() (@implements VM::DEVICES,
// vmaware.hpp ~10453-10795) and boot_logo() (@implements VM::BOOT_LOGO,
// vmaware.hpp ~10798-10921).

import (
	"hash/crc32"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(Devices, 95, devicesTechnique)
	RegisterTechnique(BootLogo, 90, bootLogoTechnique)
}

// --- Devices (@implements VM::DEVICES) ------------------------------------

type pciDevice struct {
	VendorID uint16
	DeviceID uint32
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// parseHex parses up to maxDigits hex digits from s (stopping at stopLen if
// shorter), returning the value and how many digits were consumed.
func parseHex(s string, maxDigits, stopLen int) (uint32, int, bool) {
	limit := maxDigits
	if stopLen < limit {
		limit = stopLen
	}
	var out uint32
	consumed := 0
	for consumed < limit && consumed < len(s) {
		v := hexVal(s[consumed])
		if v < 0 {
			break
		}
		out = out<<4 | uint32(v)
		consumed++
	}
	return out, consumed, consumed > 0
}

func scanTextIDs(text string, add func(vid uint16, did uint32)) {
	upper := strings.ToUpper(text)

	// USB: VID_xxxx ... PID_xxxx
	for idx := 0; ; {
		p := strings.Index(upper[idx:], "VID_")
		if p < 0 {
			break
		}
		p += idx
		v := p
		rest := upper[v+4:]
		d := strings.Index(rest, "PID_")
		if d >= 0 && d < 64 {
			dAbs := v + 4 + d
			parsedV, cv, okV := parseHex(upper[v+4:], 4, len(upper)-(v+4))
			parsedD, cd, okD := parseHex(upper[dAbs+4:], 8, len(upper)-(dAbs+4))
			if okV && okD && cv > 0 && cd > 0 {
				add(uint16(parsedV&0xFFFF), parsedD)
			}
		}
		idx = v + 4
	}

	// PCI/HDAUDIO: VEN_xxxx ... DEV_xxxx
	for idx := 0; ; {
		p := strings.Index(upper[idx:], "VEN_")
		if p < 0 {
			break
		}
		p += idx
		v := p
		rest := upper[v+4:]
		d := strings.Index(rest, "DEV_")
		if d < 0 || d >= 64 {
			idx = v + 4
			continue
		}
		dAbs := v + 4 + d

		parsedV, cv, okV := parseHex(upper[v+4:], 4, len(upper)-(v+4))
		if !okV || cv == 0 {
			idx = v + 4
			continue
		}

		devStart := dAbs + 4
		devSection := upper[devStart:]
		devLen := len(devSection)
		if amp := strings.IndexByte(devSection, '&'); amp >= 0 {
			devLen = amp
		}
		if devLen == 0 || devLen > 8 {
			idx = v + 4
			continue
		}

		parsedD, cd, okD := parseHex(upper[devStart:], 8, devLen)
		if okD && cd == devLen {
			add(uint16(parsedV&0xFFFF), parsedD)
		}
		idx = v + 4
	}

	// PCI subsystem: SUBSYS_ssssvvvv (8 hex digits: SSSSVVVV)
	for idx := 0; ; {
		p := strings.Index(upper[idx:], "SUBSYS_")
		if p < 0 {
			break
		}
		p += idx
		s := p
		parsedSub, cSub, ok := parseHex(upper[s+7:], 8, 8)
		if ok && cSub == 8 {
			subVID := uint16(parsedSub & 0xFFFF)
			subDID := (parsedSub >> 16) & 0xFFFF
			add(subVID, subDID)
		}
		idx = s + 7
	}
}

func devicesTechnique() bool {
	var devices []pciDevice
	seen := make(map[uint64]bool)
	add := func(vid uint16, did uint32) {
		key := uint64(vid)<<32 | uint64(did)
		if seen[key] {
			return
		}
		seen[key] = true
		devices = append(devices, pciDevice{VendorID: vid, DeviceID: did})
	}

	devInfo, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err == nil {
		defer windows.SetupDiDestroyDeviceInfoList(devInfo)

		for idx := 0; ; idx++ {
			devInfoData, err := windows.SetupDiEnumDeviceInfo(devInfo, idx)
			if err != nil {
				break
			}

			val, err := windows.SetupDiGetDeviceRegistryProperty(devInfo, devInfoData, windows.SPDRP_HARDWAREID)
			if err != nil {
				continue
			}

			switch ids := val.(type) {
			case []string:
				for _, s := range ids {
					scanTextIDs(s, add)
				}
			case string:
				scanTextIDs(ids, add)
			}
		}
	}

	for _, d := range devices {
		id32 := uint32(d.VendorID)<<16 | (d.DeviceID & 0xFFFF)
		id64 := uint64(d.VendorID)<<32 | uint64(d.DeviceID)

		switch id32 {
		case 0x1af40022, 0x1af41000, 0x1af41001, 0x1af41002,
			0x1af41003, 0x1af41004, 0x1af41005, 0x1af41009,
			0x1af41041, 0x1af41042, 0x1af41043, 0x1af41044,
			0x1af41045, 0x1af41048, 0x1af41049, 0x1af41050,
			0x1af41052, 0x1af41053, 0x1af4105a, 0x1af41100,
			0x1af41110, 0x1af41b36:
			return true

		case 0x15ad0710, 0x15ad0720, 0x15ad0770, 0x15ad0774,
			0x15ad0778, 0x15ad0779, 0x15ad0790, 0x15ad07a0,
			0x15ad07b0, 0x15ad07c0, 0x15ad07e0, 0x15ad07f0,
			0x15ad0801, 0x15ad0820, 0x15ad1977, 0xfffe0710,
			0x0e0f0001, 0x0e0f0002, 0x0e0f0003, 0x0e0f0004,
			0x0e0f0005, 0x0e0f0006, 0x0e0f000a, 0x0e0f8001,
			0x0e0f8002, 0x0e0f8003, 0x0e0ff80a:
			return Add(BrandVMWARE)

		case 0x1b360001, 0x1b360002, 0x1b360003, 0x1b360004,
			0x1b360005, 0x1b360008, 0x1b360009, 0x1b36000b,
			0x1b36000c, 0x1b36000d, 0x1b360010, 0x1b360011,
			0x1b360013, 0x1b360100:
			return Add(BrandQEMU)

		case 0x06270001, 0x1d1d1f1f, 0x80865845, 0x1d6b0200:
			return Add(BrandQEMU)

		case 0x10de0fe7, 0x10de0ff7, 0x10de118d, 0x10de11b0, 0x1ec6020f:
			return true

		case 0x80ee0021, 0x80ee0022, 0x80eebeef, 0x80eecafe:
			return Add(BrandVBOX)

		case 0x1ab84000, 0x1ab84005, 0x1ab84006:
			return Add(BrandParallels)

		case 0x5853c000, 0xfffd0101, 0x5853c147, 0x5853c110, 0x5853c200, 0x58530001:
			return Add(BrandXen)

		case 0x29556e61:
			return Add(BrandVPC)
		}

		switch id64 {
		case 0x0000000011061100, 0x000000001af41100, 0x000000001b361100,
			0x0000000010ec1100, 0x0000000010331100, 0x0000000080861100,
			0x0000000010131100, 0x00000000106b1100, 0x0000000010221100:
			return Add(BrandQEMU)
		case 0x0000000015ad0800:
			return Add(BrandVMWARE)
		}
	}

	return false
}

// --- BootLogo (@implements VM::BOOT_LOGO) ---------------------------------

const systemBootLogoInformation = 140

type bootLogoInfo struct {
	Flags        uint32
	BitmapOffset uint32
}

func bootLogoTechnique() bool {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return false
	}

	const maxBufferSize = 0x04000000
	var needed uint32
	err := windows.NtQuerySystemInformation(systemBootLogoInformation, nil, 0, &needed)
	st, isNTStatus := err.(windows.NTStatus)
	if !isNTStatus {
		return false
	}
	switch uint32(st) {
	case 0xC0000023, 0x80000005, 0xC0000004:
		// expected "need a bigger buffer" statuses; continue
	default:
		return false
	}

	if needed < uint32(unsafe.Sizeof(bootLogoInfo{})) || needed > maxBufferSize {
		return false
	}

	buf := make([]byte, needed)
	err2 := windows.NtQuerySystemInformation(systemBootLogoInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &needed)
	if err2 != nil {
		return false
	}
	if needed < uint32(unsafe.Sizeof(bootLogoInfo{})) || int(needed) > len(buf) {
		return false
	}

	info := (*bootLogoInfo)(unsafe.Pointer(&buf[0]))
	if info.BitmapOffset < uint32(unsafe.Sizeof(bootLogoInfo{})) || info.BitmapOffset >= needed {
		return false
	}

	bmp := buf[info.BitmapOffset:needed]

	table := crc32.MakeTable(crc32.Castagnoli)
	hash := crc32.Update(0xFFFFFFFF, table, bmp) ^ 0xFFFFFFFF

	switch hash {
	case 0x110350C5:
		return Add(BrandQEMU)
	case 0x87c39681:
		return Add(BrandHyperV)
	default:
		return false
	}
}
