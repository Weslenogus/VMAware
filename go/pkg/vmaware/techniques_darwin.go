//go:build darwin

package vmaware

import (
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func init() {
	RegisterTechnique(ThreadCount, 35, threadCount)
	RegisterTechnique(HWModel, 100, hwmodel)
	RegisterTechnique(MacMemsize, 15, hwMemsize)
	RegisterTechnique(MacIOKit, 100, ioKit)
	RegisterTechnique(IORegGrep, 100, ioregGrep)
	RegisterTechnique(MacSIP, 100, macSIP)
	RegisterTechnique(MacSys, 100, macSys)
}

// sysResult mirrors VM::util::sys_result: runs cmd through a shell (like
// popen(cmd, "r")), collects everything the child wrote to stdout, and
// strips a single trailing '\n' if present. Unlike popen, exec.Command's
// Output() distinguishes "command ran but exited non-zero" from "command
// never started" via err, but upstream ignores the exit status entirely and
// just reads whatever made it into the pipe before EOF -- so here too the
// captured bytes are used regardless of err (a command that fails to start
// yields empty output, matching popen returning nullptr -> empty string).
func sysResult(cmd string) string {
	out, _ := exec.Command("/bin/sh", "-c", cmd).Output()
	s := string(out)
	s = strings.TrimSuffix(s, "\n")
	return s
}

// isNumericASCII mirrors VM::string::is_numeric: non-empty and every byte is
// an ASCII digit.
func isNumericASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// threadCount mirrors VM::thread_count (@implements VM::THREAD_COUNT).
//
// Upstream's thread_count() is a single function shared by the
// VMAWARE_LINUX || VMAWARE_APPLE build, gated internally by
// "#if (VMAWARE_X86 && !VMAWARE_APPLE) ... #else return false; #endif". On
// an Apple build that inner condition is always false (!VMAWARE_APPLE is
// false), regardless of CPU architecture, so the macOS side of this
// technique unconditionally falls into the "#else" branch and returns
// false. There is no sysctlbyname("hw.logicalcpu"/"hw.physicalcpu") call in
// thread_count() itself -- that pair of sysctlbyname calls actually belongs
// to a helper inside the unrelated, cross-platform thread_mismatch()
// (VM::THREAD_MISMATCH) technique, not to THREAD_COUNT.
func threadCount() bool {
	return false
}

// hwmodel mirrors VM::hwmodel (@implements VM::HWMODEL).
func hwmodel() bool {
	model, err := unix.Sysctl("hw.model")
	if err != nil {
		return false
	}

	if strings.Contains(model, "Mac") {
		return false
	}

	if strings.Contains(model, "VMware") {
		return Add(BrandVMWARE)
	}

	// Assumed true since it doesn't contain "Mac" string.
	return true
}

// hwMemsize mirrors VM::hw_memsize (@implements VM::MAC_MEMSIZE).
func hwMemsize() bool {
	ram := sysResult("sysctl -n hw.memsize")

	if ram == "0" {
		return false
	}

	if !isNumericASCII(ram) {
		return false
	}

	ramU64, err := strconv.ParseUint(ram, 10, 64)
	if err != nil {
		return false
	}

	const limit = uint64(4000000000) // 4GB

	return ramU64 <= limit
}

// ioKit mirrors VM::io_kit (@implements VM::MAC_IOKIT).
func ioKit() bool {
	platform := sysResult("ioreg -rd1 -c IOPlatformExpertDevice")
	board := sysResult("ioreg -rd1 -c board-id")
	manufacturer := sysResult("ioreg -rd1 -c manufacturer")
	keyboard := sysResult("ioreg -lw0 -p IODeviceTree")

	checkPlatform := func() bool {
		if platform == "" {
			return false
		}

		for i := 0; i < len(platform); i++ {
			c := platform[i]
			if c < '0' || c > '9' {
				return false
			}
		}

		return platform == "0"
	}

	checkBoard := func() bool {
		if board == "" {
			return false
		}

		if strings.Contains(board, "Mac") {
			return false
		}

		if strings.Contains(board, "VirtualBox") {
			return Add(BrandVBOX)
		}

		if strings.Contains(board, "VMware") {
			return Add(BrandVMWARE)
		}

		return false
	}

	checkManufacturer := func() bool {
		if manufacturer == "" {
			return false
		}

		if strings.Contains(manufacturer, "Apple") {
			return false
		}

		if strings.Contains(manufacturer, "innotek") {
			return Add(BrandVBOX)
		}

		return false
	}

	checkKeyboard := func() bool {
		if keyboard == "" {
			return false
		}

		if strings.Contains(keyboard, "Virtual Machine") {
			return true
		}

		return false
	}

	return checkPlatform() || checkBoard() || checkManufacturer() || checkKeyboard()
}

// ioregGrep mirrors VM::ioreg_grep (@implements VM::IOREG_GREP).
func ioregGrep() bool {
	checkUSB := func() bool {
		usb := sysResult(`ioreg -rd1 -c IOUSBHostDevice | grep "USB Vendor Name"`)

		if strings.Contains(usb, "Apple") {
			return false
		}

		if strings.Contains(usb, "VirtualBox") {
			return Add(BrandVBOX)
		}

		return false
	}

	checkROM := func() bool {
		rom := sysResult(`system_profiler SPHardwareDataType | grep "Boot ROM Version"`)

		if strings.Contains(rom, "VirtualBox") {
			return Add(BrandVBOX)
		}

		return false
	}

	return checkUSB() || checkROM()
}

// macSIP mirrors VM::mac_sip (@implements VM::MAC_SIP).
//
// Note: upstream also checks "if (!result) { return false; }" after calling
// sys_result("csrutil status"), but util::sys_result always returns a valid
// (non-null) unique_ptr<string> -- even on a popen failure it returns one
// wrapping an empty string -- so that null check can never actually fire.
// sysResult here mirrors that same "always returns a string, empty on
// failure" behavior, so the check is faithfully absent rather than reimplemented
// as dead code.
func macSIP() bool {
	hvPresent, err := unix.SysctlUint32("kern.hv_vmm_present")
	if err != nil {
		return false
	}

	if hvPresent != 0 {
		return true
	}

	tmp := sysResult("csrutil status")

	if idx := strings.IndexByte(tmp, '\n'); idx != -1 {
		tmp = tmp[:idx]
	}

	if strings.Contains(tmp, "unknown") {
		return false
	}

	return strings.Contains(tmp, "disabled")
}

// macSys mirrors VM::mac_sys (@implements VM::MAC_SYS).
func macSys() bool {
	const keyword = "virtual machine"

	output := strings.ToLower(sysResult("system_profiler SPHardwareDataType"))

	return strings.Contains(output, keyword)
}
