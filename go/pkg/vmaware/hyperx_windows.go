//go:build windows

package vmaware

// Port of VM::util::hyper_x() (vmaware.hpp lines ~5622-6110) plus the small
// Windows-only helpers right after it (is_windows_11, is_windows_8_or_newer,
// is_32bit_execution_disabled, get_manufacturer_and_model,
// is_x86_process_on_arm) that hyper_x() and several techniques in this
// package depend on.

import (
	"strings"
	"sync"
	"unsafe"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ntSuccess mirrors the NT_SUCCESS(status) macro: true when the status's
// high bit (the "error" severity bit) is clear.
func ntSuccess(st windows.NTStatus) bool {
	return int32(st) >= 0
}

// --- util::is_windows_11 / is_windows_8_or_newer -----------------------

func isWindows11() bool {
	vi := windows.RtlGetVersion()
	return vi.BuildNumber >= 22000
}

func isWindows8OrNewer() bool {
	vi := windows.RtlGetVersion()
	return vi.MajorVersion > 6 || (vi.MajorVersion == 6 && vi.MinorVersion >= 2)
}

// --- util::is_admin ------------------------------------------------------

func isAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// --- util::is_32bit_execution_disabled -----------------------------------

var procGetSystemWow64DirectoryW = procOrNil(modKernel32, "GetSystemWow64DirectoryW")

func is32BitExecutionDisabled() bool {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return false
	}
	if procGetSystemWow64DirectoryW == nil {
		return true
	}
	var buf [260]uint16
	r1, _, _ := procGetSystemWow64DirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	// Upstream returns true unconditionally on any failure path (including
	// ERROR_CALL_NOT_IMPLEMENTED/ERROR_PATH_NOT_FOUND, and even otherwise);
	// only a successful call yields false.
	return r1 == 0
}

// --- util::get_manufacturer_and_model -------------------------------------

var (
	biosInfoOnce  sync.Once
	biosInfoMan   string
	biosInfoModel string
)

func isPlaceholderBiosString(s string) bool {
	if s == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "system product name", "to be filled by o.e.m.", "default string", "not specified", "none":
		return true
	}
	return false
}

func readBiosRegString(valueName string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return ""
	}
	return v
}

// getManufacturerAndModel mirrors util::get_manufacturer_and_model, cached
// for the process lifetime exactly like memo::bios_info.
func getManufacturerAndModel() (manufacturer, model string, ok bool) {
	biosInfoOnce.Do(func() {
		if v := readBiosRegString("SystemManufacturer"); !isPlaceholderBiosString(v) {
			biosInfoMan = v
		} else if v := readBiosRegString("BaseBoardManufacturer"); !isPlaceholderBiosString(v) {
			biosInfoMan = v
		}

		if v := readBiosRegString("SystemProductName"); !isPlaceholderBiosString(v) {
			biosInfoModel = v
		} else if v := readBiosRegString("BaseBoardProduct"); !isPlaceholderBiosString(v) {
			biosInfoModel = v
		} else if v := readBiosRegString("SystemSKU"); !isPlaceholderBiosString(v) {
			biosInfoModel = v
		} else if v := readBiosRegString("BaseBoardVersion"); !isPlaceholderBiosString(v) {
			biosInfoModel = v
		}
	})
	return biosInfoMan, biosInfoModel, biosInfoMan != "" || biosInfoModel != ""
}

// --- util::is_x86_process_on_arm ------------------------------------------

const (
	imageFileMachineI386  = 0x014c
	imageFileMachineAmd64 = 0x8664
	imageFileMachineArm64 = 0xAA64
	imageFileMachineArmNT = 0x01c4
)

var (
	procIsWow64Process2          = procOrNil(modKernel32, "IsWow64Process2")
	procNtQueryInformationProcOK = procOrNil(modNtdll, "NtQueryInformationProcess")

	x86OnArmOnce sync.Once
	x86OnArm     bool
)

func isX86ProcessOnARM() bool {
	x86OnArmOnce.Do(func() {
		brand := cpuprobe.GetBrand()
		if strings.Contains(brand, "Virtual CPU") {
			x86OnArm = true
			return
		}

		var procMachine, nativeMachine uint16
		if procIsWow64Process2 != nil {
			r1, _, _ := procIsWow64Process2.Call(
				uintptr(windows.CurrentProcess()),
				uintptr(unsafe.Pointer(&procMachine)),
				uintptr(unsafe.Pointer(&nativeMachine)),
			)
			if r1 != 0 {
				if (nativeMachine == imageFileMachineArm64 || nativeMachine == imageFileMachineArmNT) &&
					(procMachine == imageFileMachineI386 || procMachine == imageFileMachineAmd64) {
					x86OnArm = true
					return
				}
			}
		}

		if (nativeMachine == imageFileMachineArm64 || nativeMachine == imageFileMachineArmNT) && procNtQueryInformationProcOK != nil {
			type processMachineInformation struct {
				ProcessMachine uint16
				Res0           uint16
				Attributes     uint32
			}
			var pmInfo processMachineInformation
			const processMachineInternalInformation = 90
			r1, _, _ := procNtQueryInformationProcOK.Call(
				uintptr(windows.CurrentProcess()),
				processMachineInternalInformation,
				uintptr(unsafe.Pointer(&pmInfo)),
				unsafe.Sizeof(pmInfo),
				0,
			)
			if int32(r1) >= 0 {
				if pmInfo.ProcessMachine == imageFileMachineI386 || pmInfo.ProcessMachine == imageFileMachineAmd64 {
					x86OnArm = true
					return
				}
			}
		}

		if cpuprobe.IsLeafSupported(cpuprobe.LeafHypervisor) {
			vendor := cpuprobe.CPUManufacturer(cpuprobe.LeafHypervisor)
			if vendor == "VirtualApple" || vendor == "PowerVM Lx86" {
				x86OnArm = true
			}
		}
	})
	return x86OnArm
}

// --- hyper_x() helpers -----------------------------------------------------

func hyperVIsHyperVPresent() bool {
	_, _, ecx, _ := cpuprobe.CPUID(cpuprobe.LeafFeatures)
	return (ecx>>31)&1 != 0
}

func hyperVIsRootPartition() bool {
	_, ebx, _, _ := cpuprobe.CPUID(cpuprobe.LeafHvPrivileges)
	return ebx&1 != 0
}

func hyperVEax() uint32 {
	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafHypervisor)
	return eax & 0xFF
}

func hyperVIsNested() bool {
	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafHvInterface)
	if eax != 0x31237648 { // "Hv#1"
		return false
	}
	eax, _, _, _ = cpuprobe.CPUID(cpuprobe.LeafHvNested)
	guestLevel := (eax >> 10) & 0xF
	return guestLevel != 0
}

// isHalHPresent mirrors hyper_x()'s is_halh_present lambda: scans the
// SystemObjectSecurityMode-adjacent SystemHandleInformation... no -
// specifically SystemInformationClass 0x16 (SystemPagedPoolInformation on
// some docs, but upstream uses it purely as an opaque tag-list buffer) for
// a "HalH" tag, indicating the HAL's machine-check init path ran in a
// hypervisor-aware context.
func isHalHPresent() bool {
	const sysBootInfoClass = 0x16
	const halHTag = 0x486C6148 // "HalH"

	size := uint32(1024 * 1024)
	var buf []byte
	for {
		buf = make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(sysBootInfoClass, unsafe.Pointer(&buf[0]), uint32(len(buf)), &needed)
		if err == nil {
			break
		}
		st, ok := err.(windows.NTStatus)
		if !ok || st != windows.STATUS_INFO_LENGTH_MISMATCH {
			return true
		}
		size = needed + 4096
	}

	type entryStruct struct {
		Tag uint32
		PA  uint32
		PF  uint32
		PU  uintptr
		NPA uint32
		NPF uint32
		NPU uintptr
	}
	type infoStruct struct {
		Count   uint32
		TagInfo [1]entryStruct
	}

	headerOffset := int(unsafe.Offsetof(infoStruct{}.TagInfo))
	if len(buf) < headerOffset {
		return true
	}

	info := (*infoStruct)(unsafe.Pointer(&buf[0]))
	entrySize := int(unsafe.Sizeof(entryStruct{}))
	bytesAvailable := len(buf) - headerOffset
	maxPossibleCount := bytesAvailable / entrySize

	count := int(info.Count)
	if count > maxPossibleCount {
		count = maxPossibleCount
	}

	entries := unsafe.Slice((*entryStruct)(unsafe.Pointer(&buf[headerOffset])), count)
	for i := 0; i < count; i++ {
		if entries[i].Tag == halHTag {
			return true
		}
	}
	return false
}

// tbsProcs bundles the four tbs.dll entry points hyper_x()'s is_log_present
// (and measured_boot()/tpm() elsewhere) resolve dynamically.
type tbsProcs struct {
	mod           *windows.LazyDLL
	getTCGLogEx   *windows.LazyProc // Tbsi_Get_TCG_Log_Ex
	contextCreate *windows.LazyProc // Tbsi_Context_Create
	getTCGLog     *windows.LazyProc // Tbsi_Get_TCG_Log
	contextClose  *windows.LazyProc // Tbsip_Context_Close
	submitCommand *windows.LazyProc // Tbsip_Submit_Command
}

var (
	tbsOnce  sync.Once
	tbsCache *tbsProcs
)

func loadTBS() *tbsProcs {
	tbsOnce.Do(func() {
		mod := windows.NewLazySystemDLL("tbs.dll")
		if err := mod.Load(); err != nil {
			return
		}
		tbsCache = &tbsProcs{
			mod:           mod,
			getTCGLogEx:   procOrNil(mod, "Tbsi_Get_TCG_Log_Ex"),
			contextCreate: procOrNil(mod, "Tbsi_Context_Create"),
			getTCGLog:     procOrNil(mod, "Tbsi_Get_TCG_Log"),
			contextClose:  procOrNil(mod, "Tbsip_Context_Close"),
			submitCommand: procOrNil(mod, "Tbsip_Submit_Command"),
		}
	})
	return tbsCache
}

const tbsInsufficientBuffer = 0x80284005

// fetchTCGLog fetches the raw TCG PCR event log via tbs.dll, trying
// Tbsi_Get_TCG_Log_Ex first and falling back to the
// Tbsi_Context_Create/Tbsi_Get_TCG_Log/Tbsip_Context_Close trio, mirroring
// hyper_x()'s is_log_present (and shared, with a different log-type
// argument, by measured_boot()).
func fetchTCGLog(logType uint32) (buf []byte, ok bool) {
	tbs := loadTBS()
	if tbs == nil {
		return nil, false
	}

	if tbs.getTCGLogEx != nil {
		var logSize uint32
		r1, _, _ := tbs.getTCGLogEx.Call(uintptr(logType), 0, uintptr(unsafe.Pointer(&logSize)))
		if (r1 == 0 || r1 == tbsInsufficientBuffer) && logSize > 0 {
			b := make([]byte, logSize)
			r1, _, _ = tbs.getTCGLogEx.Call(uintptr(logType), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&logSize)))
			if r1 == 0 {
				return b[:logSize], true
			}
		}
	}

	if tbs.contextCreate != nil && tbs.getTCGLog != nil && tbs.contextClose != nil {
		type tbsContextParams struct {
			Version uint32
		}
		params := tbsContextParams{Version: 1}
		var context uintptr
		r1, _, _ := tbs.contextCreate.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&context)))
		if r1 == 0 {
			defer tbs.contextClose.Call(context)
			var logSize uint32
			r1, _, _ = tbs.getTCGLog.Call(context, 0, uintptr(unsafe.Pointer(&logSize)))
			if (r1 == 0 || r1 == tbsInsufficientBuffer) && logSize > 0 {
				b := make([]byte, logSize)
				r1, _, _ = tbs.getTCGLog.Call(context, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&logSize)))
				if r1 == 0 {
					return b[:logSize], true
				}
			}
		}
	}

	return nil, false
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

var hyperVLogTargets = []string{
	"hvix64.exe", "hvax64.exe", "hvloader.dll", "securekernel.exe",
	"winresume.efi", "hiberresume.exe", "hiberrsm.exe",
}

// scanHyperVEventTargets mirrors is_log_present's scan_targets lambda: a
// case-insensitive UTF-16LE substring search, restricted to PCR 11/13.
func scanHyperVEventTargets(pcr uint32, eventData []byte) bool {
	if pcr != 11 && pcr != 13 {
		return false
	}
	for _, target := range hyperVLogTargets {
		targetLen := len(target)
		byteLen := targetLen * 2
		if len(eventData) < byteLen {
			continue
		}
		for i := 0; i+byteLen <= len(eventData); i++ {
			match := true
			for j := 0; j < targetLen; j++ {
				lo := eventData[i+j*2]
				hi := eventData[i+j*2+1]
				logChar := uint16(lo) | uint16(hi)<<8
				if logChar >= 'A' && logChar <= 'Z' {
					logChar = logChar - 'A' + 'a'
				}
				targetChar := uint16(target[j])
				if targetChar >= 'A' && targetChar <= 'Z' {
					targetChar = targetChar - 'A' + 'a'
				}
				if logChar != targetChar {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

type algSizePair struct {
	AlgID      uint16
	DigestSize uint16
}

// isLogPresent mirrors hyper_x()'s is_log_present lambda: parses the raw
// TCG PCR event log (both the legacy SHA1-only format and the crypto-agile
// TCG_PCR_EVENT2 format) looking for a Hyper-V boot component name in PCR
// 11 or 13. On any inability to get/parse a log it returns true ("assume
// legitimate, don't false-flag"), matching upstream exactly.
func isLogPresent() bool {
	logBuffer, ok := fetchTCGLog(0)
	if !ok {
		return true
	}

	if len(logBuffer) < 32 {
		return true
	}

	eventDataSize := le32(logBuffer[28:32])
	if eventDataSize > uint32(len(logBuffer))-32 {
		return true
	}
	firstEventSize := 32 + int(eventDataSize)
	firstEventData := logBuffer[32 : 32+eventDataSize]

	cryptoAgile := eventDataSize >= 16 && string(firstEventData[:15]) == "Spec ID Event03"

	algSizes := []algSizePair{
		{0x0004, 20}, {0x000B, 32}, {0x000C, 48}, {0x000D, 64}, {0x0012, 32},
	}

	if cryptoAgile {
		const specIDHeaderSize = 28 // offsetof(tcg_efi_spec_id_event_struct_header, number_of_algorithms) + 4
		if uint32(len(firstEventData)) < specIDHeaderSize {
			return true
		}
		numAlgorithms := le32(firstEventData[24:28])
		pAlg := specIDHeaderSize
		if uint32(len(firstEventData))-specIDHeaderSize >= numAlgorithms*4 {
			for i := uint32(0); i < numAlgorithms; i++ {
				if pAlg+4 > len(firstEventData) {
					return true
				}
				algID := le16(firstEventData[pAlg : pAlg+2])
				digestSize := le16(firstEventData[pAlg+2 : pAlg+4])
				updated := false
				for j := range algSizes {
					if algSizes[j].AlgID == algID {
						algSizes[j].DigestSize = digestSize
						updated = true
						break
					}
				}
				if !updated {
					algSizes = append(algSizes, algSizePair{algID, digestSize})
				}
				pAlg += 4
			}
		} else {
			return true
		}
	}

	getDigestSize := func(algID uint16) (uint16, bool) {
		for _, a := range algSizes {
			if a.AlgID == algID {
				return a.DigestSize, true
			}
		}
		return 0, false
	}

	offset := firstEventSize
	logSize := len(logBuffer)

	for offset < logSize {
		if cryptoAgile {
			if offset+12 > logSize {
				return true
			}
			pcr := le32(logBuffer[offset : offset+4])
			digestCount := le32(logBuffer[offset+8 : offset+12])

			temp := offset + 12
			algError := false
			for i := uint32(0); i < digestCount; i++ {
				if logSize-temp < 2 {
					algError = true
					break
				}
				algID := le16(logBuffer[temp : temp+2])
				digestSize, found := getDigestSize(algID)
				if !found || digestSize == 0 {
					algError = true
					break
				}
				if logSize-temp-2 < int(digestSize) {
					algError = true
					break
				}
				temp += 2 + int(digestSize)
			}
			if algError || temp+4 > logSize {
				return true
			}
			eventSize := le32(logBuffer[temp : temp+4])
			if int(eventSize) > logSize-temp-4 {
				return true
			}
			eventData := logBuffer[temp+4 : temp+4+int(eventSize)]
			offset = temp + 4 + int(eventSize)

			if scanHyperVEventTargets(pcr, eventData) {
				return true // event data found: confirms genuine Hyper-V
			}
		} else {
			if offset+32 > logSize {
				return true
			}
			pcr := le32(logBuffer[offset : offset+4])
			eventSize := le32(logBuffer[offset+28 : offset+32])
			if int(eventSize) > logSize-offset-32 {
				return true
			}
			eventData := logBuffer[offset+32 : offset+32+int(eventSize)]
			offset += 32 + int(eventSize)

			if scanHyperVEventTargets(pcr, eventData) {
				return true
			}
		}
	}

	// Parsed the whole log without error and without a match: mirrors
	// upstream's "return found_hyperv" (false) at the end of the do-while.
	return false
}

// hyperXState memoization (mirrors memo::hyperx).
var (
	hyperXOnce   sync.Once
	hyperXResult HyperXState
)

// hyperX mirrors VM::util::hyper_x() for the Windows build.
func hyperX() HyperXState {
	hyperXOnce.Do(func() {
		hyperXResult = computeHyperX()
	})
	return hyperXResult
}

func computeHyperX() HyperXState {
	enlightenmentStr := cpuprobe.CPUManufacturer(cpuprobe.LeafHvEnlightenment)
	if enlightenmentStr != "" && strings.Contains(enlightenmentStr, "KVM") {
		Add(BrandQEMUKVMHyperV)
		return HyperVEnlightenment
	}

	if hyperVIsNested() {
		return HyperVNestedVM
	}

	if !hyperVIsRootPartition() {
		if hyperVEax() == 11 && hyperVIsHyperVPresent() {
			Add(BrandHyperV)
			return HyperVRealVM
		}
		return HyperVUnknown
	}

	brandStr := cpuprobe.CPUManufacturer(cpuprobe.LeafHypervisor)
	isHyperVHost := enlightenmentStr != "" && brandStr == "Microsoft Hv"

	if isAdmin() && isWindows11() {
		isHyperVHost = isHyperVHost && isHalHPresent()
	}

	isHyperVHost = isHyperVHost && isLogPresent()

	if isHyperVHost {
		Add(BrandHyperVRoot)
		return HyperVHost
	}

	AddWithScore(BrandNullBrand, 150)
	return HyperVSpoofed
}
