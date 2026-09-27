//go:build windows

package vmaware

// Port of kernel_objects() (@implements VM::KERNEL_OBJECTS, vmaware.hpp
// ~13600-13767) and nvram() (@implements VM::NVRAM, vmaware.hpp
// ~13767-14164).

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	RegisterTechnique(KernelObjects, 100, kernelObjectsTechnique)
	RegisterTechnique(NVRAM, 100, nvramTechnique)
}

// --- KernelObjects (@implements VM::KERNEL_OBJECTS) -----------------------

var (
	procNtOpenDirectoryObject  = procOrNil(modNtdll, "NtOpenDirectoryObject")
	procNtQueryDirectoryObject = procOrNil(modNtdll, "NtQueryDirectoryObject")
)

// objectDirectoryInformation mirrors OBJECT_DIRECTORY_INFORMATION:
// { UNICODE_STRING Name; UNICODE_STRING TypeName; }.
type objectDirectoryInformation struct {
	Name     windows.NTUnicodeString
	TypeName windows.NTUnicodeString
}

func kernelObjectsTechnique() bool {
	if procNtOpenDirectoryObject == nil || procNtQueryDirectoryObject == nil || procNtClose == nil {
		return false
	}

	const directoryQuery = 0x0001
	const statusNoMoreEntries = 0x8000001A

	dirName, err := windows.NewNTUnicodeString(`\Device`)
	if err != nil {
		return false
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: dirName,
		Attributes: windows.OBJ_CASE_INSENSITIVE,
	}

	var dir windows.Handle
	r1, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&dir)), directoryQuery, uintptr(unsafe.Pointer(&oa)))
	if int32(r1) < 0 || dir == 0 {
		return false
	}
	defer procNtClose.Call(uintptr(dir))

	buf := make([]byte, 4096)
	const maxDirBuffer = 64 * 1024
	var context uint32
	detected := false
	var detectedBrand BrandEnum = BrandNullBrand

	for {
		var returnedLength uint32
		r1, _, _ = procNtQueryDirectoryObject.Call(
			uintptr(dir),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // ReturnSingleEntry = TRUE
			0, // RestartScan = FALSE
			uintptr(unsafe.Pointer(&context)),
			uintptr(unsafe.Pointer(&returnedLength)),
		)

		if uint32(r1) == statusNoMoreEntries {
			break
		}
		if int32(r1) < 0 {
			if returnedLength > uint32(len(buf)) {
				newSize := returnedLength
				if newSize > maxDirBuffer {
					newSize = maxDirBuffer
				}
				if newSize <= uint32(len(buf)) {
					break
				}
				buf = make([]byte, newSize)
				continue
			}
			break
		}

		if returnedLength < uint32(unsafe.Sizeof(objectDirectoryInformation{})) || returnedLength > uint32(len(buf)) {
			break
		}

		info := (*objectDirectoryInformation)(unsafe.Pointer(&buf[0]))
		nameBytes := info.Name.Length
		namePtr := uintptr(unsafe.Pointer(info.Name.Buffer))

		if nameBytes == 0 || nameBytes%2 != 0 || namePtr%2 != 0 {
			continue
		}

		bufBase := uintptr(unsafe.Pointer(&buf[0]))
		bufEnd := bufBase + uintptr(returnedLength)
		minValidPtr := bufBase + unsafe.Sizeof(objectDirectoryInformation{})

		if namePtr < minValidPtr || namePtr >= bufEnd || uintptr(nameBytes) > bufEnd-namePtr {
			continue
		}

		wname := unsafe.Slice(info.Name.Buffer, int(nameBytes)/2)
		name := windows.UTF16ToString(wname)

		if strings.EqualFold(name, "VmGenerationCounter") || strings.EqualFold(name, "VmGid") {
			detected = true
			detectedBrand = BrandHyperV
			break
		}
	}

	if detected {
		return Add(detectedBrand)
	}
	return false
}

// --- NVRAM (@implements VM::NVRAM) ----------------------------------------

var (
	procNtEnumerateSystemEnvironmentValuesEx = procOrNil(modNtdll, "NtEnumerateSystemEnvironmentValuesEx")
	procNtQuerySystemEnvironmentValueEx      = procOrNil(modNtdll, "NtQuerySystemEnvironmentValueEx")
)

// nvramVariableNameHeader mirrors VARIABLE_NAME's fixed prefix:
// { ULONG NextEntryOffset; GUID VendorGuid; WCHAR Name[1]; }.
type nvramVariableNameHeader struct {
	NextEntryOffset uint32
	VendorGUID      windows.GUID
}

func nvramReadVariable(name string, guid windows.GUID) ([]byte, bool) {
	if procNtQuerySystemEnvironmentValueEx == nil || procNtAllocateVirtualMemory == nil || procNtFreeVirtualMemory == nil {
		return nil, false
	}
	if len(name) == 0 || len(name) >= 256 {
		return nil, false
	}

	nameU16 := windows.StringToUTF16(name)
	nameLen := len(nameU16) - 1
	uni := windows.NTUnicodeString{
		Length:        uint16(nameLen * 2),
		MaximumLength: uint16(len(nameU16) * 2),
		Buffer:        &nameU16[0],
	}

	var requiredSize uint32
	procNtQuerySystemEnvironmentValueEx.Call(uintptr(unsafe.Pointer(&uni)), uintptr(unsafe.Pointer(&guid)), 0, uintptr(unsafe.Pointer(&requiredSize)), 0)
	if requiredSize == 0 {
		return nil, false
	}

	allocSize := uintptr(requiredSize)
	if allocSize < 0x1000 {
		allocSize = 0x1000
	}
	var base unsafe.Pointer
	regionSize := allocSize
	const memCommit = 0x1000
	const memReserve = 0x2000
	const pageReadWrite = 0x04
	r1, _, _ := procNtAllocateVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageReadWrite)
	if int32(r1) < 0 || base == nil {
		return nil, false
	}

	r1, _, _ = procNtQuerySystemEnvironmentValueEx.Call(uintptr(unsafe.Pointer(&uni)), uintptr(unsafe.Pointer(&guid)), uintptr(base), uintptr(unsafe.Pointer(&requiredSize)), 0)
	if int32(r1) != 0 {
		freeSize := uintptr(0)
		procNtFreeVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&freeSize)), 0x8000)
		return nil, false
	}

	out := make([]byte, requiredSize)
	copy(out, unsafe.Slice((*byte)(base), requiredSize))

	freeSize := uintptr(0)
	procNtFreeVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&freeSize)), 0x8000)

	return out, true
}

func bufferContainsASCIICI(data []byte, pat string) bool {
	return strings.Contains(strings.ToLower(string(data)), strings.ToLower(pat))
}

func bufferContainsUTF16CI(data []byte, pat string) bool {
	s := utf16LEToString(data)
	return strings.Contains(strings.ToLower(s), strings.ToLower(pat))
}

func nvramTechnique() bool {
	if !isAdmin() {
		return false
	}
	if procNtEnumerateSystemEnvironmentValuesEx == nil || procNtAllocateVirtualMemory == nil || procNtFreeVirtualMemory == nil {
		return false
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSystemEnvironmentPrivilege"), &luid); err != nil {
		return false
	}

	tpEnable := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	var previous windows.Tokenprivileges
	previousSize := uint32(unsafe.Sizeof(previous))
	if err := windows.AdjustTokenPrivileges(token, false, &tpEnable, previousSize, &previous, &previousSize); err != nil {
		return false
	}
	// AdjustTokenPrivileges can succeed yet silently drop the privilege; the
	// upstream check (GetLastError() == ERROR_NOT_ALL_ASSIGNED) doesn't have
	// a direct Go equivalent through this wrapper, so this is best-effort.
	defer windows.AdjustTokenPrivileges(token, false, &previous, previousSize, nil, nil)

	var enumBase unsafe.Pointer
	var bufferRequiredLength uint32
	procNtEnumerateSystemEnvironmentValuesEx.Call(1, 0, uintptr(unsafe.Pointer(&bufferRequiredLength)))
	if bufferRequiredLength == 0 {
		return false
	}

	enumAllocSize := uintptr(bufferRequiredLength)
	r1, _, _ := procNtAllocateVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&enumBase)), 0, uintptr(unsafe.Pointer(&enumAllocSize)), 0x1000|0x2000, 0x04)
	if int32(r1) < 0 || enumBase == nil {
		return false
	}
	freeEnum := func() {
		if enumBase != nil {
			freeSize := uintptr(0)
			procNtFreeVirtualMemory.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&enumBase)), uintptr(unsafe.Pointer(&freeSize)), 0x8000)
			enumBase = nil
		}
	}
	defer freeEnum()

	r1, _, _ = procNtEnumerateSystemEnvironmentValuesEx.Call(1, uintptr(enumBase), uintptr(unsafe.Pointer(&bufferRequiredLength)))
	if int32(r1) != 0 {
		return false
	}

	const maxNameByteLimit = 4096
	bufferTotalSize := uintptr(bufferRequiredLength)
	var pkDefaultBuf []byte
	haveePKDefault := false

	currentOffset := uintptr(0)
	for currentOffset < bufferTotalSize {
		if bufferTotalSize-currentOffset < unsafe.Sizeof(nvramVariableNameHeader{}) {
			break
		}
		hdr := (*nvramVariableNameHeader)(unsafe.Add(enumBase, currentOffset))

		nameStructOffset := unsafe.Sizeof(nvramVariableNameHeader{})
		var nameMaxBytes uintptr
		if hdr.NextEntryOffset != 0 {
			nextEntry := uintptr(hdr.NextEntryOffset)
			if nextEntry <= nameStructOffset {
				break
			}
			if nextEntry > bufferTotalSize-currentOffset {
				break
			}
			nameMaxBytes = nextEntry - nameStructOffset
		} else {
			if currentOffset+nameStructOffset >= bufferTotalSize {
				break
			}
			nameMaxBytes = bufferTotalSize - (currentOffset + nameStructOffset)
		}
		if nameMaxBytes > maxNameByteLimit {
			nameMaxBytes = maxNameByteLimit
		}

		var varName string
		if nameMaxBytes >= 2 {
			namePtr := (*uint16)(unsafe.Add(enumBase, currentOffset+nameStructOffset))
			maxChars := nameMaxBytes / 2
			nameSlice := unsafe.Slice(namePtr, int(maxChars))
			realChars := 0
			for realChars < int(maxChars) && nameSlice[realChars] != 0 {
				realChars++
			}
			if realChars == int(maxChars) {
				break
			}
			varName = windows.UTF16ToString(nameSlice[:realChars])
		}

		if varName != "" && strings.HasPrefix(varName, "VMM") {
			return true
		}

		if varName == "PKDefault" && !haveePKDefault {
			if data, ok := nvramReadVariable(varName, hdr.VendorGUID); ok {
				pkDefaultBuf = data
				haveePKDefault = true
			}
		}

		if hdr.NextEntryOffset == 0 {
			break
		}
		nextVarOffset := currentOffset + uintptr(hdr.NextEntryOffset)
		if nextVarOffset <= currentOffset || nextVarOffset > bufferTotalSize {
			break
		}
		currentOffset = nextVarOffset
	}

	if len(pkDefaultBuf) > 0 {
		if bufferContainsUTF16CI(pkDefaultBuf, "red hat") || bufferContainsASCIICI(pkDefaultBuf, "red hat") {
			return Add(BrandQEMU)
		}
	}

	return false
}
