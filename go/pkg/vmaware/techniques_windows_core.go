//go:build windows

package vmaware

// Port of vmaware.hpp lines ~11791-13050 (Windows techniques): dll(),
// wine(), power_capabilities(), gamarue(), mutex(), cuckoo(), display(),
// drivers(), gpu_capabilities(), device_handles(), virtual_processors(),
// virtual_registry(), acpi_signature().
//
// vpc_invalid() and vmware_str() (also in that source range) live in
// techniques_windows_vpc.go since they need the SEH substitute from
// seh_windows.go.

import (
	"strings"
	"unsafe"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(DLL, 50, dllTechnique)
	RegisterTechnique(Wine, 150, wineTechnique)
	RegisterTechnique(PowerCapabilities, 25, powerCapabilitiesTechnique)
	RegisterTechnique(Gamarue, 30, gamarueTechnique)
	RegisterTechnique(Mutex, 100, mutexTechnique)
	RegisterTechnique(Cuckoo, 30, cuckooTechnique)
	RegisterTechnique(Display, 25, displayTechnique)
	RegisterTechnique(Drivers, 100, driversTechnique)
	RegisterTechnique(GPUCapabilities, 20, gpuCapabilitiesTechnique)
	RegisterTechnique(Handles, 100, deviceHandlesTechnique)
	RegisterTechnique(VirtualProcessors, 100, virtualProcessorsTechnique)
	RegisterTechnique(VirtualRegistry, 90, virtualRegistryTechnique)
	RegisterTechnique(ACPISignature, 100, acpiSignatureTechnique)
}

// --- DLL (@implements VM::DLL) --------------------------------------------

var dllBrandTable = []struct {
	name  string
	brand BrandEnum
}{
	{"sbiedll.dll", BrandSandboxie},
	{"pstorec.dll", BrandCWSandbox},
	{"vmcheck.dll", BrandVPC},
	{"cmdvrt32.dll", BrandComodo},
	{"cmdvrt64.dll", BrandComodo},
	{"cuckoomon.dll", BrandCuckoo},
	{"SxIn.dll", BrandQihoo},
}

func dllTechnique() bool {
	for _, x := range dllBrandTable {
		h, err := getModuleHandle(x.name)
		if err == nil && h != 0 {
			return Add(x.brand)
		}
	}
	return false
}

// --- Wine (@implements VM::WINE) ------------------------------------------

var (
	procMulDiv = procOrNil(modKernel32, "MulDiv")
)

func wineTechnique() bool {
	if h, err := getModuleHandle("ntdll.dll"); err == nil {
		if p, _ := windows.GetProcAddress(h, "wine_get_version"); p != 0 {
			return Add(BrandWine)
		}
	}

	kernel32, err := getModuleHandle("kernel32.dll")
	if err != nil {
		return false
	}
	if p, _ := windows.GetProcAddress(kernel32, "wine_get_unix_file_name"); p != 0 {
		return Add(BrandWine)
	}

	if procMulDiv != nil {
		var intMin int32 = -2147483648
		arg := uintptr(uint32(intMin))
		r1, _, _ := procMulDiv.Call(1, arg, arg)
		if int32(r1) == 0 {
			return Add(BrandWine)
		}
	}

	if isWindows8OrNewer() {
		p, err := windows.GetProcAddress(kernel32, "IsNativeVhdBoot")
		if err != nil || p == 0 {
			return Add(BrandWine)
		}
		// Upstream then calls IsNativeVhdBoot and checks whether Wine's stub
		// implementation raises EXCEPTION_WINE_STUB via SEH. Actually invoking
		// an arbitrary, unauthenticated code pointer purely to see whether it
		// throws isn't something we can safely reproduce without the same
		// exception-filter machinery genuine callers rely on elsewhere in
		// this port (guardedAbortCall is for our own known-shape asm leaves,
		// not arbitrary kernel32 exports), so this last sub-check is
		// intentionally left as a no-op: the export-presence check above
		// already covers the common case.
	}

	return false
}

// --- PowerCapabilities (@implements VM::POWER_CAPABILITIES) --------------

var procNtPowerInformation = procOrNil(modNtdll, "NtPowerInformation")

type systemPowerCapabilities struct {
	PowerButtonPresent        byte
	SleepButtonPresent        byte
	LidPresent                byte
	SystemS1                  byte
	SystemS2                  byte
	SystemS3                  byte
	SystemS4                  byte
	SystemS5                  byte
	HiberFilePresent          byte
	FullWake                  byte
	VideoDimPresent           byte
	ApmPresent                byte
	UpsPresent                byte
	ThermalControl            byte
	ProcessorThrottle         byte
	ProcessorMinThrottle      byte
	ProcessorMaxThrottle      byte
	FastSystemS4              byte
	Hiberboot                 byte
	WakeAlarmPresent          byte
	AoAc                      byte
	DiskSpinDown              byte
	HiberFileType             byte
	AoAcConnectivitySupported byte
	spare3                    [6]byte
	SystemBatteriesPresent    byte
	BatteriesAreShortTerm     byte
	// BatteryScale[3] and remaining reserved fields aren't needed; the
	// buffer we pass NtPowerInformation is sized to the real struct so the
	// kernel writes past this Go view harmlessly (see powerCapabilitiesTechnique).
}

func powerCapabilitiesTechnique() bool {
	if procNtPowerInformation == nil {
		return false
	}

	const systemPowerCapabilitiesLevel = 4 // SYSTEM_POWER_CAPABILITIES / SystemPowerCapabilities
	// The real SYSTEM_POWER_CAPABILITIES struct is larger than the subset we
	// modeled above; allocate generously so NtPowerInformation always has
	// enough room regardless of exact struct size on a given SDK.
	buf := make([]byte, 256)
	r1, _, _ := procNtPowerInformation.Call(systemPowerCapabilitiesLevel, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if windows.NTStatus(r1) != windows.STATUS_SUCCESS {
		return false
	}

	caps := (*systemPowerCapabilities)(unsafe.Pointer(&buf[0]))
	s0 := caps.AoAc != 0
	s1 := caps.SystemS1 != 0
	s2 := caps.SystemS2 != 0
	s3 := caps.SystemS3 != 0
	s4 := caps.SystemS4 != 0
	hiber := caps.HiberFilePresent != 0

	isPhysicalPattern := (s0 || s3) && (s4 || hiber)
	if isPhysicalPattern {
		return false
	}

	isVMPattern := !(s0 || s3 || s4 || hiber) && (s1 || s2)
	if isVMPattern {
		return true
	}

	noSleepStates := !s0 && !s1 && !s2 && !s3 && !s4 && !hiber
	return noSleepStates
}

// --- Gamarue (@implements VM::GAMARUE) ------------------------------------

var (
	procNtOpenKey       = procOrNil(modNtdll, "NtOpenKey")
	procNtQueryValueKey = procOrNil(modNtdll, "NtQueryValueKey")
	procNtClose         = procOrNil(modNtdll, "NtClose")
)

var gamarueProductIDTable = []struct {
	productID string
	brand     BrandEnum
}{
	{"55274-640-2673064-23950", BrandJoebox},
	{"76487-644-3177037-23510", BrandCWSandbox},
	{"76487-337-8429955-22614", BrandAnubis},
}

func gamarueTechnique() bool {
	if procNtOpenKey == nil || procNtQueryValueKey == nil || procNtClose == nil {
		return false
	}

	keyName, err := windows.NewNTUnicodeString(`\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return false
	}

	oa := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: keyName,
		Attributes: windows.OBJ_CASE_INSENSITIVE,
	}

	const keyQueryOnly = 0x0001 | 0x0100 // KEY_QUERY_VALUE | KEY_WOW64_64KEY
	var key windows.Handle
	r1, _, _ := procNtOpenKey.Call(uintptr(unsafe.Pointer(&key)), keyQueryOnly, uintptr(unsafe.Pointer(&oa)))
	if int32(r1) < 0 || key == 0 {
		return false
	}
	defer procNtClose.Call(uintptr(key))

	valueName, err := windows.NewNTUnicodeString("ProductId")
	if err != nil {
		return false
	}

	var buf [128]byte
	var resultLength uint32
	const keyValuePartialInformation = 2
	r1, _, _ = procNtQueryValueKey.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(valueName)),
		keyValuePartialInformation,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&resultLength)),
	)
	if int32(r1) < 0 {
		return false
	}

	const headerSize = 12 // offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data)
	if resultLength <= headerSize || resultLength > uint32(len(buf)) {
		return false
	}

	kvType := le32(buf[4:8])
	const regSZ = 1
	if kvType != regSZ {
		return false
	}

	dataLength := le32(buf[8:12])
	maxSafeDataLen := resultLength - headerSize
	actualDataLen := dataLength
	if actualDataLen > maxSafeDataLen {
		actualDataLen = maxSafeDataLen
	}
	if actualDataLen < 2 {
		return false
	}

	data := buf[headerSize : headerSize+actualDataLen]
	productID := utf16LEToString(data)

	const targetLength = 23
	if len(productID) != targetLength {
		return false
	}

	for _, target := range gamarueProductIDTable {
		if productID == target.productID {
			return Add(target.brand)
		}
	}
	return false
}

// utf16LEToString decodes a raw little-endian UTF-16 byte slice (no
// alignment guarantees) into a Go string, stopping at a NUL code unit if
// present (matching windows.UTF16ToString's own behavior).
func utf16LEToString(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return windows.UTF16ToString(units)
}

// --- Mutex (@implements VM::MUTEX) ----------------------------------------

var procNtOpenMutant = procOrNil(modNtdll, "NtOpenMutant")

func tryOpenMutex(name string) bool {
	const mutantQueryState = 0x0001

	attempts := []string{`\BaseNamedObjects\` + name, name}
	for _, path := range attempts {
		u, err := windows.NewNTUnicodeString(path)
		if err != nil {
			continue
		}
		oa := windows.OBJECT_ATTRIBUTES{
			Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			ObjectName: u,
			Attributes: windows.OBJ_CASE_INSENSITIVE,
		}
		var h windows.Handle
		r1, _, _ := procNtOpenMutant.Call(uintptr(unsafe.Pointer(&h)), mutantQueryState, uintptr(unsafe.Pointer(&oa)))
		if int32(r1) >= 0 {
			if h != 0 {
				procNtClose.Call(uintptr(h))
			}
			return true
		}
	}
	return false
}

func mutexTechnique() bool {
	if procNtOpenMutant == nil || procNtClose == nil {
		return false
	}

	if tryOpenMutex("Sandboxie_SingleInstanceMutex_Control") || tryOpenMutex("SBIE_BOXED_ServiceInitComplete_Mutex1") {
		return Add(BrandSandboxie)
	}
	if tryOpenMutex("MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex") {
		return Add(BrandVPC)
	}
	return false
}

// --- Cuckoo (@implements VM::CUCKOO) --------------------------------------

var procNtOpenFile = procOrNil(modNtdll, "NtOpenFile")

func cuckooTechnique() bool {
	if procNtOpenFile == nil || procNtClose == nil {
		return false
	}

	type target struct {
		path          string
		desiredAccess uint32
		shareAccess   uint32
		openOptions   uint32
	}

	const (
		fileReadAttributes        = 0x0080
		fileShareRead             = 0x00000001
		fileShareWrite            = 0x00000002
		fileShareDelete           = 0x00000004
		fileOpen                  = 0x00000001
		fileSynchronousIONonalert = 0x00000020
		fileDirectoryFile         = 0x00000001
		fileNonDirectoryFile      = 0x00000040
		synchronize               = 0x00100000
	)

	targets := []target{
		{`\??\C:\Cuckoo`, fileReadAttributes, fileShareRead | fileShareWrite | fileShareDelete, fileOpen | fileSynchronousIONonalert | fileDirectoryFile},
		{`\??\pipe\cuckoo`, fileReadAttributes, fileShareRead | fileShareWrite, fileOpen | fileSynchronousIONonalert},
	}

	for _, t := range targets {
		u, err := windows.NewNTUnicodeString(t.path)
		if err != nil {
			continue
		}
		oa := windows.OBJECT_ATTRIBUTES{
			Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			ObjectName: u,
			Attributes: windows.OBJ_CASE_INSENSITIVE,
		}
		var h windows.Handle
		var iosb windows.IO_STATUS_BLOCK
		r1, _, _ := procNtOpenFile.Call(
			uintptr(unsafe.Pointer(&h)),
			uintptr(t.desiredAccess),
			uintptr(unsafe.Pointer(&oa)),
			uintptr(unsafe.Pointer(&iosb)),
			uintptr(t.shareAccess),
			uintptr(t.openOptions),
		)
		if int32(r1) >= 0 {
			if h != 0 {
				procNtClose.Call(uintptr(h))
			}
			return true
		}
	}
	return false
}

// --- Display (@implements VM::DISPLAY) ------------------------------------

var (
	procGetDC         = procOrNil(modUser32, "GetDC")
	procReleaseDC     = procOrNil(modUser32, "ReleaseDC")
	procGetDeviceCaps = procOrNil(modGdi32, "GetDeviceCaps")
)

const (
	gdiCapsBitsPixel     = 12
	gdiCapsPlanes        = 14
	gdiCapsLogPixelsX    = 88
	gdiCapsColorMgmtCaps = 121
	gdiCapsGammaRamp     = 0x00000001 // CM_GAMMA_RAMP
)

func displayTechnique() bool {
	if procGetDC == nil || procGetDeviceCaps == nil {
		return false
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return false
	}
	defer procReleaseDC.Call(0, hdc)

	bpp, _, _ := procGetDeviceCaps.Call(hdc, gdiCapsBitsPixel)
	planes, _, _ := procGetDeviceCaps.Call(hdc, gdiCapsPlanes)
	logPix, _, _ := procGetDeviceCaps.Call(hdc, gdiCapsLogPixelsX)

	total := int32(bpp) * int32(planes)
	return total != 32 || int32(logPix) < 90
}

// --- GPUCapabilities (@implements VM::GPU_CAPABILITIES) -------------------

func gpuCapabilitiesTechnique() bool {
	if procGetDC == nil || procGetDeviceCaps == nil {
		return false
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return false
	}
	defer procReleaseDC.Call(0, hdc)

	colorCaps, _, _ := procGetDeviceCaps.Call(hdc, gdiCapsColorMgmtCaps)
	return int32(colorCaps)&gdiCapsGammaRamp == 0
}

// --- Handles / device_handles (@implements VM::HANDLES) -------------------

func checkDevicePresence(nativePath string) bool {
	u, err := windows.NewNTUnicodeString(nativePath)
	if err != nil {
		return false
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: u,
		Attributes: windows.OBJ_CASE_INSENSITIVE,
	}

	const (
		fileReadAttributes        = 0x0080
		synchronize               = 0x00100000
		fileShareRead             = 0x00000001
		fileShareWrite            = 0x00000002
		fileNonDirectoryFile      = 0x00000040
		fileSynchronousIONonalert = 0x00000020
	)

	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	r1, _, _ := procNtOpenFile.Call(
		uintptr(unsafe.Pointer(&h)),
		fileReadAttributes|synchronize,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iosb)),
		fileShareRead|fileShareWrite,
		fileNonDirectoryFile|fileSynchronousIONonalert,
	)
	if int32(r1) >= 0 {
		if h != 0 {
			procNtClose.Call(uintptr(h))
		}
		return true
	}

	switch uint32(r1) {
	case 0xC0000022, 0xC0000043, 0xC00000AD: // STATUS_ACCESS_DENIED / STATUS_SHARING_VIOLATION / STATUS_PIPE_BUSY
		return true
	}
	return false
}

func deviceHandlesTechnique() bool {
	if procNtOpenFile == nil || procNtClose == nil {
		return false
	}

	vboxPaths := []string{`\??\VBoxMiniRdrDN`, `\??\pipe\VBoxMiniRdDN`, `\??\VBoxTrayIPC`, `\??\pipe\VBoxTrayIPC`}
	for _, p := range vboxPaths {
		if checkDevicePresence(p) {
			return Add(BrandVBOX)
		}
	}
	if checkDevicePresence(`\??\HGFS`) {
		return Add(BrandVMWARE)
	}
	if checkDevicePresence(`\??\pipe\cuckoo`) {
		return Add(BrandCuckoo)
	}
	return false
}

// --- VirtualProcessors (@implements VM::VIRTUAL_PROCESSORS) ---------------

func virtualProcessorsTechnique() bool {
	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafHypervisor)
	if eax < cpuprobe.LeafHvProcessors || eax > 0x400000FF {
		return false
	}
	maxVP, maxLP, _, _ := cpuprobe.CPUID(cpuprobe.LeafHvProcessors)
	if maxVP == 0xFFFFFFFF || maxLP == 0 {
		return true
	}
	return false
}

// --- VirtualRegistry (@implements VM::VIRTUAL_REGISTRY) -------------------

var procNtQueryObject = procOrNil(modNtdll, "NtQueryObject")

func virtualRegistryTechnique() bool {
	if procNtOpenKey == nil || procNtQueryObject == nil || procNtClose == nil {
		return false
	}

	rawTarget := `\REGISTRY\USER`
	targetU16 := windows.StringToUTF16(rawTarget)
	targetCharCount := len(targetU16) - 1 // exclude the implicit NUL StringToUTF16 appends
	targetByteLength := uint16(targetCharCount * 2)

	keyPath := windows.NTUnicodeString{
		Length:        targetByteLength,
		MaximumLength: targetByteLength + 2,
		Buffer:        &targetU16[0],
	}

	oa := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: &keyPath,
		Attributes: windows.OBJ_CASE_INSENSITIVE,
	}

	const keyRead = 0x20019
	var key windows.Handle
	r1, _, _ := procNtOpenKey.Call(uintptr(unsafe.Pointer(&key)), keyRead, uintptr(unsafe.Pointer(&oa)))
	if int32(r1) < 0 {
		return false
	}

	var buf [1024]byte
	var returnedLength uint32
	const objectNameInformation = 1
	r1, _, _ = procNtQueryObject.Call(
		uintptr(key),
		objectNameInformation,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&returnedLength)),
	)
	procNtClose.Call(uintptr(key))

	const statusInfoLengthMismatch = 0xC0000004
	const statusBufferOverflow = 0x80000005
	switch uint32(r1) {
	case statusInfoLengthMismatch, statusBufferOverflow:
		return Add(BrandSandboxie)
	}
	if int32(r1) < 0 {
		return false
	}

	// OBJECT_NAME_INFORMATION is just { UNICODE_STRING Name; }.
	if returnedLength < uint32(unsafe.Sizeof(windows.NTUnicodeString{})) || returnedLength > uint32(len(buf)) {
		return false
	}

	nameHdr := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if nameHdr.Buffer == nil || nameHdr.Length == 0 {
		return false
	}

	bufStart := uintptr(unsafe.Pointer(&buf[0]))
	validEnd := bufStart + uintptr(returnedLength)
	strStart := uintptr(unsafe.Pointer(nameHdr.Buffer))
	if strStart < bufStart || strStart >= validEnd || uintptr(nameHdr.Length) > validEnd-strStart || strStart%2 != 0 {
		return false
	}

	actualName := windows.UTF16PtrToString(nameHdr.Buffer)

	mismatch := len(actualName) != targetCharCount || !strings.EqualFold(actualName, rawTarget)
	if mismatch {
		return Add(BrandSandboxie)
	}
	return false
}

// --- Drivers (@implements VM::DRIVERS) ------------------------------------

var (
	procNtAllocateVirtualMemory = procOrNil(modNtdll, "NtAllocateVirtualMemory")
	procNtFreeVirtualMemory     = procOrNil(modNtdll, "NtFreeVirtualMemory")
	procNtQueryKey              = procOrNil(modNtdll, "NtQueryKey")
)

func driversTechnique() bool {
	if brand := driversScanModules(); brand != BrandNullBrand {
		return Add(brand)
	}
	return driversScanDeviceClasses()
}

// driversScanModules mirrors drivers()'s SystemModuleInformation scan.
func driversScanModules() BrandEnum {
	if procNtQuerySystemInformationOK == nil || procNtAllocateVirtualMemory == nil || procNtFreeVirtualMemory == nil {
		return BrandNullBrand
	}

	const systemModuleInformation = 11
	var needed uint32
	err := windows.NtQuerySystemInformation(systemModuleInformation, nil, 0, &needed)
	st, _ := err.(windows.NTStatus)
	if err == nil || st != windows.STATUS_INFO_LENGTH_MISMATCH || needed == 0 {
		return BrandNullBrand
	}

	size := uintptr(needed) + 4096*4
	var base unsafe.Pointer
	regionSize := size
	const memCommit = 0x1000
	const memReserve = 0x2000
	const pageReadWrite = 0x04
	r1, _, _ := procNtAllocateVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageReadWrite)
	if int32(r1) < 0 || base == nil {
		return BrandNullBrand
	}
	defer func() {
		freeSize := uintptr(0)
		procNtFreeVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&freeSize)), 0x8000)
	}()

	var returnLength uint32
	moduleErr := windows.NtQuerySystemInformation(systemModuleInformation, base, uint32(regionSize), &returnLength)
	if moduleErr != nil {
		return BrandNullBrand
	}

	// _SYSTEM_MODULE_INFORMATION_EX is { ULONG NumberOfModules; _SYSTEM_MODULE_INFORMATION Module[1]; }
	// and _SYSTEM_MODULE_INFORMATION starts with PVOID Reserved[2], so on a
	// pointer size > 4 the compiler pads NumberOfModules up to that pointer
	// size before Module[0] begins.
	ptrSize := unsafe.Sizeof(uintptr(0))
	headerSize := ptrSize
	if headerSize < 4 {
		headerSize = 4
	}
	// Reserved[2] + ImageBaseAddress (3 pointers) + ImageSize + Flags (2 ULONG)
	// + Index + NameLength + LoadCount + PathLength (4 USHORT) + ImageName[256].
	imageNameOffsetInModule := 3*ptrSize + 4 + 4 + 2 + 2 + 2 + 2
	moduleEntrySize := imageNameOffsetInModule + 256
	if returnLength <= uint32(headerSize) {
		return BrandNullBrand
	}

	numberOfModules := *(*uint32)(base)
	maxModules := (uintptr(returnLength) - headerSize) / moduleEntrySize
	if uintptr(numberOfModules) > maxModules {
		numberOfModules = uint32(maxModules)
	}

	for i := uint32(0); i < numberOfModules; i++ {
		entryAddr := unsafe.Add(base, headerSize+uintptr(i)*moduleEntrySize)
		nameAddr := unsafe.Add(entryAddr, imageNameOffsetInModule)
		nameBytes := unsafe.Slice((*byte)(nameAddr), 256)
		name := strings.ToLower(cStringFromBytes(nameBytes))

		if strings.Contains(name, "vboxguest") || strings.Contains(name, "vboxmouse") || strings.Contains(name, "vboxsf") {
			return BrandVBOX
		}
		if strings.Contains(name, "vmusbmouse") || strings.Contains(name, "vmmemctl") {
			return BrandVMWARE
		}
	}
	return BrandNullBrand
}

func cStringFromBytes(b []byte) string {
	if idx := indexByteOrLen(b, 0); idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

// driversScanDeviceClasses mirrors drivers()'s IVSHMEM/LGIdd device-class
// interface GUID scan.
func driversScanDeviceClasses() bool {
	if procNtOpenKey == nil || procNtQueryKey == nil || procNtClose == nil {
		return false
	}

	guids := []string{
		`{DF576976-569D-4672-95A0-F57E4EA0B210}`, // IVSHMEM
		`{997B0B66-B74C-4017-9A89-E4AAD41D3780}`, // LGIdd
	}

	for _, guid := range guids {
		path := `\Registry\Machine\SYSTEM\CurrentControlSet\Control\DeviceClasses\` + guid
		u, err := windows.NewNTUnicodeString(path)
		if err != nil {
			continue
		}
		oa := windows.OBJECT_ATTRIBUTES{
			Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			ObjectName: u,
			Attributes: windows.OBJ_CASE_INSENSITIVE,
		}

		const keyRead = 0x20019
		var key windows.Handle
		r1, _, _ := procNtOpenKey.Call(uintptr(unsafe.Pointer(&key)), keyRead, uintptr(unsafe.Pointer(&oa)))
		if int32(r1) < 0 || key == 0 {
			continue
		}

		var buf [512]byte
		var returnedLen uint32
		const keyFullInformation = 2
		r1, _, _ = procNtQueryKey.Call(uintptr(key), keyFullInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&returnedLen)))
		procNtClose.Call(uintptr(key))

		// KEY_FULL_INFORMATION: LastWriteTime(8) + TitleIndex(4) + ClassOffset(4)
		// + ClassLength(4) + SubKeys(4) -> SubKeys sits at byte offset 20.
		const statusBufferOverflow = 0x80000005
		const subKeysOffset = 20
		ok := int32(r1) >= 0 || uint32(r1) == statusBufferOverflow
		if ok && returnedLen >= subKeysOffset+4 {
			subKeys := le32(buf[subKeysOffset : subKeysOffset+4])
			if subKeys > 0 {
				return Add(BrandQEMU)
			}
		}
	}
	return false
}

var procNtQuerySystemInformationOK = procOrNil(modNtdll, "NtQuerySystemInformation")
