//go:build windows

package vmaware

// Port of acpi_signature() (@implements VM::ACPI_SIGNATURE,
// vmaware.hpp ~12920-13049): enumerates every device in the system and
// inspects its DEVPKEY_Device_LocationPaths multi-string property (plus, for
// the PNP0A06 synthetic ACPI device case, its instance ID) for QEMU/Hyper-V
// signatures.

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procSetupDiGetDevicePropertyW = procOrNil(modSetupapi, "SetupDiGetDevicePropertyW")

// devPropKeyLocationPaths mirrors DEVPKEY_Device_LocationPaths
// ({a45c254e-df1c-4efd-8020-67d146a850e0}, 37).
var devPropKeyLocationPaths = windows.DEVPROPKEY{
	FmtID: windows.DEVPROPGUID{
		Data1: 0xa45c254e,
		Data2: 0xdf1c,
		Data3: 0x4efd,
		Data4: [8]byte{0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0},
	},
	PID: 37,
}

var acpiExcludedTokens = []string{
	"GFX", "IGD", "IGFX", "IGPU", "VGA", "VIDEO", "DISPLAY", "GPU",
	"PCIROOT", "PNP0A03", "PNP0A08", "PCH", "PXS", "PEG", "PEGP",
}

func acpiHasExcludedToken(s string) bool {
	for _, tok := range acpiExcludedTokens {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

var acpiVMSignatures = []string{"#ACPI(VMOD)", "#ACPI(VMBS)", "#VMBUS(", "#VPCI("}

func acpiSignatureTechnique() bool {
	if procSetupDiGetDevicePropertyW == nil {
		return false
	}

	devInfo, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return false
	}
	defer windows.SetupDiDestroyDeviceInfoList(devInfo)

	for idx := 0; ; idx++ {
		devInfoData, err := windows.SetupDiEnumDeviceInfo(devInfo, idx)
		if err != nil {
			break
		}

		instID, _ := windows.SetupDiGetDeviceInstanceId(devInfo, devInfoData)

		if strings.Contains(instID, "PNP0A06") &&
			(strings.Contains(instID, "HOTPLUG") || strings.Contains(instID, "GPE0") || strings.Contains(instID, "SMI")) {
			return Add(BrandQEMU)
		}

		values, ok := acpiGetLocationPaths(devInfo, devInfoData)
		if !ok {
			continue
		}

		for _, p := range values {
			if strings.Contains(p, "ACPI(DRAC)") {
				return Add(BrandQEMU)
			}

			if instID != "" && strings.Contains(instID, "VEN_1022") {
				if strings.Contains(p, "PCI(1F00)") || strings.Contains(p, "PCI(1F02)") || strings.Contains(p, "PCI(1F03)") {
					return Add(BrandQEMU)
				}
			}

			if !acpiHasExcludedToken(p) {
				for _, sig := range acpiVMSignatures {
					if strings.Contains(p, sig) {
						return Add(BrandHyperV)
					}
				}
			}
		}
	}

	return false
}

// acpiGetLocationPaths resolves DEVPKEY_Device_LocationPaths (a
// DEVPROP_TYPE_STRING_LIST) directly via SetupDiGetDevicePropertyW, since
// x/sys/windows's SetupDiGetDeviceProperty wrapper only decodes
// DEVPROP_TYPE_STRING.
func acpiGetLocationPaths(devInfo windows.DevInfo, devInfoData *windows.DevInfoData) ([]string, bool) {
	const devPropTypeStringList = 0x00000012 | 0x00002000
	const errorInsufficientBuffer = 122

	var propType uint32
	var requiredSize uint32

	for i := 0; i < 4; i++ {
		bufSize := requiredSize
		var bufPtr *byte
		var buf []byte
		if bufSize > 0 {
			buf = make([]byte, bufSize)
			bufPtr = &buf[0]
		}

		r1, _, callErr := procSetupDiGetDevicePropertyW.Call(
			uintptr(devInfo),
			uintptr(unsafe.Pointer(devInfoData)),
			uintptr(unsafe.Pointer(&devPropKeyLocationPaths)),
			uintptr(unsafe.Pointer(&propType)),
			uintptr(unsafe.Pointer(bufPtr)),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&requiredSize)),
			0,
		)
		if r1 != 0 {
			if propType != devPropTypeStringList || requiredSize == 0 || requiredSize%2 != 0 {
				return nil, false
			}
			units := make([]uint16, requiredSize/2)
			for j := range units {
				units[j] = uint16(buf[j*2]) | uint16(buf[j*2+1])<<8
			}
			return splitMultiSZ(units), true
		}

		errno, _ := callErr.(windows.Errno)
		if uintptr(errno) != errorInsufficientBuffer || requiredSize == 0 {
			return nil, false
		}
		// Loop again with the now-known requiredSize.
	}

	return nil, false
}

// splitMultiSZ splits a REG_MULTI_SZ-shaped (NUL-separated, double-NUL
// terminated) UTF-16 buffer into individual strings.
func splitMultiSZ(units []uint16) []string {
	var out []string
	start := 0
	for i := 0; i < len(units); i++ {
		if units[i] == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(units[start:i]))
			}
			start = i + 1
		}
	}
	return out
}
