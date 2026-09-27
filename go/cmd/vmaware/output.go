package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	vm "github.com/weslenogus/vmaware/go/pkg/vmaware"
)

func printLine(msg string) {
	fmt.Println(msg)
}

// color mirrors output.cpp's color(u8 score) (the CLI's own copy, distinct
// from any library-side color helper).
func color(score uint8) string {
	if argBits_.test(argNoAnsi) {
		return ""
	}

	if argBits_.test(argDynamic) {
		switch {
		case score == 0:
			return red
		case score <= 12:
			return red
		case score <= 25:
			return redOrange
		case score < 50:
			return redOrange
		case score <= 62:
			return orange
		case score <= 75:
			return greenOrange
		case score < 100:
			return green
		case score == 100:
			return green
		}
		return ""
	}

	if score == 100 {
		return green
	}
	return red
}

func consolePause() {
	fmt.Print("Press Enter to exit...")
	var dummy string
	fmt.Scanln(&dummy)
}

// arePermsRequired mirrors output.cpp's are_perms_required (CLI_LINUX only):
// a small set of Linux techniques that silently no-op without root.
func arePermsRequired(flag vm.EnumFlag) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if isAdmin() {
		return false
	}
	switch flag {
	case vm.Dmidecode, vm.Dmesg, vm.QEMUUSB, vm.KMSG, vm.SMBIOSVMBit, vm.NVRAM:
		return true
	default:
		return false
	}
}

// isDisabledCLI mirrors output.cpp's is_disabled: whether flag was named by
// --disable (and --all wasn't given, which overrides every disable).
func isDisabledCLI(flag vm.EnumFlag) bool {
	if argBits_.test(argAll) {
		return false
	}
	for _, f := range vm.DisabledTechniques {
		if f == flag {
			return true
		}
	}
	return false
}

// isUnsupportedCLI mirrors output.cpp's is_unsupported: whether flag applies
// to the OS this binary was built for.
func isUnsupportedCLI(flag vm.EnumFlag) bool {
	switch runtime.GOOS {
	case "linux":
		return !((flag >= vm.HypervisorBit && flag <= vm.KGTSignature) ||
			(uint8(flag) >= vm.LinuxStart && uint8(flag) <= vm.LinuxEnd))
	case "windows":
		return !((flag >= vm.HypervisorBit && flag <= vm.KGTSignature) ||
			(uint8(flag) >= vm.WindowsStart && uint8(flag) <= vm.WindowsEnd))
	case "darwin":
		return !((flag >= vm.HypervisorBit && flag <= vm.KGTSignature) ||
			(uint8(flag) >= vm.MacOSStart && uint8(flag) <= vm.MacOSEnd))
	default:
		return false
	}
}

// stringToTechnique mirrors output.cpp's string_to_technique.
func stringToTechnique(name string) (vm.EnumFlag, bool) {
	for i := vm.TechniqueBegin; i < vm.TechniqueEnd; i++ {
		flag := vm.EnumFlag(i)
		if vm.FlagToString(flag) == name {
			return flag, true
		}
	}
	return vm.NullArg, false
}

// isVMBrandMultiple mirrors output.cpp's is_vm_brand_multiple.
func isVMBrandMultiple(brand string) bool {
	return strings.Contains(brand, " or ")
}

// getVMDescription mirrors output.cpp's get_vm_description, backed by the
// mechanically transcribed brandDescriptions table (brand_descriptions.go).
func getVMDescription(brandName string) string {
	if isVMBrandMultiple(brandName) {
		return ""
	}
	for b, desc := range brandDescriptions {
		if vm.BrandEnumToString(b) == brandName {
			return desc
		}
	}
	return ""
}

// checker mirrors output.cpp's checker().
func checker(flag vm.EnumFlag, message string) {
	var enumName string
	if argBits_.test(argEnums) {
		enumName = grey + " [VM::" + vm.FlagToString(flag) + "]" + ansiExit
	}

	if isDisabledCLI(flag) {
		disabledCount++
		printLine(fmt.Sprintf("%s %sSkipped %s.%s", tagSkipped, grey, message, ansiExit))
		return
	}

	if isUnsupportedCLI(flag) {
		unsupportedCount++
		if !argBits_.test(argAll) {
			return
		}
	}

	supportedCount++

	start := time.Now()
	result, _ := vm.Check(flag)
	elapsed := time.Since(start)

	if argBits_.test(argDetectedOnly) && !result {
		return
	}

	if arePermsRequired(flag) {
		noPermsCount++
		_, _ = vm.Check(flag)
		printLine(fmt.Sprintf("%s %sSkipped %s.%s", tagNoPerms, grey, message, ansiExit))
		return
	}

	ms := float64(elapsed) / float64(time.Millisecond)

	if result {
		printLine(fmt.Sprintf("%s%s %sChecking %s...%s%s", white, tagDetected, white, message, ansiExit, enumName))
	} else {
		printLine(fmt.Sprintf("%s %sChecking %s...%s%s", tagNotDetected, grey, message, ansiExit, enumName))
	}
	_ = dim
	_ = ms
}

// parseDisableToken mirrors output.cpp's parse_disable_token: a
// comma-separated list of technique names following --disable.
func parseDisableToken(token string) bool {
	names := strings.Split(token, ",")

	for _, name := range names {
		if name == "" {
			continue
		}

		flag, found := stringToTechnique(name)
		if !found {
			fmt.Fprintf(os.Stderr, "Unknown technique \"%s\", aborting\n", name)
			return false
		}

		vm.DisabledTechniques = append(vm.DisabledTechniques, flag)
	}

	return true
}

// generateJSON mirrors output.cpp's generate_json.
func generateJSON(output string) {
	v := vm.NewVMAware(vm.Multiple)

	type jsonResult struct {
		IsDetected             bool     `json:"is_detected"`
		Brand                  string   `json:"brand"`
		Conclusion             string   `json:"conclusion"`
		Percentage             int      `json:"percentage"`
		DetectedTechniqueCount int      `json:"detected_technique_count"`
		VMType                 string   `json:"vm_type"`
		DetectedTechniques     []string `json:"detected_techniques"`
	}

	result := jsonResult{
		IsDetected:             v.IsVM,
		Brand:                  v.Brand,
		Conclusion:             v.Conclusion,
		Percentage:             int(v.Percentage),
		DetectedTechniqueCount: int(v.TechniqueCount),
		VMType:                 v.Type,
		DetectedTechniques:     v.DetectedTechniqueStrings,
	}
	if result.DetectedTechniques == nil {
		result.DetectedTechniques = []string{}
	}

	data, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode JSON")
		return
	}

	if err := os.WriteFile(output, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open/create file")
	}
}

func getTechniqueCount() uint32 {
	return uint32(vm.NewVMAware().TechniqueCount)
}

func flagArg(condition bool, flag vm.EnumFlag) vm.EnumFlag {
	if condition {
		return flag
	}
	return vm.NullArg
}

func runStdout(highThreshold, all, dynamic bool) int {
	detected := vm.Detect(
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	)
	if detected {
		return 0
	}
	return 1
}

func runPercent(highThreshold, all, dynamic bool) uint32 {
	return uint32(vm.Percentage(
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	))
}

func runDetect(highThreshold, all, dynamic bool) bool {
	return vm.Detect(
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	)
}

func runBrand(highThreshold, all, dynamic bool) string {
	return vm.Brand(
		vm.Multiple,
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	)
}

func runType(highThreshold, all, dynamic bool) string {
	return vm.Type(
		vm.Multiple,
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	)
}

func runConclusion(highThreshold, all, dynamic bool) string {
	return vm.Conclusion(
		vm.Multiple,
		flagArg(highThreshold, vm.HighThreshold),
		flagArg(all, vm.All),
		flagArg(dynamic, vm.Dynamic),
	)
}

// general mirrors output.cpp's general(): the full technique-by-technique
// walkthrough followed by the summary block.
func general(highThreshold, all, dynamic bool, outputFile string) {
	highThreshArg := flagArg(highThreshold, vm.HighThreshold)
	allArg := flagArg(all, vm.All)
	dynamicArg := flagArg(dynamic, vm.Dynamic)

	notesEnabled := runtime.GOOS == "linux" && !argBits_.test(argNotes)

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open/create file \"%s\"\n", outputFile)
		} else {
			f.Close()
			argBits_.set(argNoAnsi)
		}
	}

	if argBits_.test(argNoAnsi) {
		tagDetected = "[  DETECTED  ]"
		tagNotDetected = "[NOT DETECTED]"
		tagSkipped = "[  DISABLED  ]"
		tagNotes = "[    NOTE    ]"
		tagNoPerms = "[  NO PERMS  ]"
		boldStr, underline, ansiExit = "", "", ""
		red, orange, green = "", "", ""
		redOrange, greenOrange = "", ""
		grey, white = "", ""
	}

	if runtime.GOOS == "linux" && notesEnabled && !isAdmin() {
		printLine("Running under root might give better results")
	}

	if argBits_.test(argRich) {
		printLine(grey + "Note: --rich (the Windows TUI) is not implemented in this Go port; falling back to plain output." + ansiExit)
	}

	t1 := time.Now()

	checker(vm.VMID, "VMID")
	checker(vm.CPUBrand, "CPU brand")
	checker(vm.HypervisorBit, "CPUID hypervisor bit")
	checker(vm.HypervisorStr, "hypervisor str")
	checker(vm.ThreadCount, "thread count")
	checker(vm.MAC, "MAC addresses")
	checker(vm.Temperature, "temperature")
	checker(vm.Systemd, "systemd virtualisation")
	checker(vm.CVendor, "chassis vendor")
	checker(vm.CType, "chassis type")
	checker(vm.DockerEnv, "Dockerenv")
	checker(vm.Dmidecode, "dmidecode output")
	checker(vm.Dmesg, "dmesg output")
	checker(vm.HWMon, "hwmon presence")
	checker(vm.DLL, "DLLs")
	checker(vm.Wine, "Wine")
	checker(vm.HWModel, "hw.model")
	checker(vm.Processes, "processes")
	checker(vm.LinuxUserHost, "default Linux user/host")
	checker(vm.Gamarue, "gamarue ransomware technique")
	checker(vm.BochsCPU, "BOCHS CPU techniques")
	checker(vm.MacMemsize, "MacOS hw.memsize")
	checker(vm.MacIOKit, "MacOS registry IO-kit")
	checker(vm.IORegGrep, "IO registry grep")
	checker(vm.MacSIP, "MacOS SIP")
	checker(vm.Handles, "device handles")
	checker(vm.VPCInvalid, "VPC invalid instructions")
	checker(vm.SystemRegisters, "task segment and descriptor tables")
	checker(vm.VMwareStr, "STR instruction")
	checker(vm.Mutex, "mutex strings")
	checker(vm.ThreadMismatch, "thread count mismatch")
	checker(vm.Cuckoo, "Cuckoo")
	checker(vm.Azure, "Azure Hyper-V")
	checker(vm.Display, "display")
	checker(vm.BluestacksFolders, "BlueStacks folders")
	checker(vm.CPUIDSignature, "CPUID signatures")
	checker(vm.KGTSignature, "Intel KGT signature")
	checker(vm.QEMUVirtualDMI, "QEMU virtual DMI directory")
	checker(vm.QEMUUSB, "QEMU USB")
	checker(vm.HypervisorDir, "hypervisor directory (Linux)")
	checker(vm.UMLCPU, "User-mode Linux CPU")
	checker(vm.KMSG, "/dev/kmsg hypervisor message")
	checker(vm.VBoxModule, "VBox kernel module")
	checker(vm.SysinfoProc, "/proc/sysinfo")
	checker(vm.DMIScan, "DMI scan")
	checker(vm.SMBIOSVMBit, "SMBIOS VM bit")
	checker(vm.PodmanFile, "podman file")
	checker(vm.WSLProc, "WSL string in /proc")
	checker(vm.Drivers, "drivers")
	checker(vm.Disk, "virtual disks")
	checker(vm.GPUCapabilities, "virtual GPUs")
	checker(vm.PowerCapabilities, "power capabilities")
	checker(vm.QEMUFwCfg, "QEMU fw_cfg device")
	checker(vm.VirtualProcessors, "virtual processors")
	checker(vm.AMDSevMSR, "AMD-SEV MSR")
	checker(vm.VirtualRegistry, "registry emulation")
	checker(vm.Firmware, "firmware")
	checker(vm.FileAccessHistory, "low file access count")
	checker(vm.ContainerPID, "container PID")
	checker(vm.Devices, "PCI vendor/device ID")
	checker(vm.ACPISignature, "ACPI device signatures")
	checker(vm.UD, "undefined exceptions")
	checker(vm.DBVM, "DBVM hypervisor")
	checker(vm.BootLogo, "boot logo")
	checker(vm.MacSys, "system profiler")
	checker(vm.KernelObjects, "kernel objects")
	checker(vm.NVRAM, "NVRAM")
	checker(vm.MSR, "model specific registers")
	checker(vm.CPUHeuristic, "instruction capabilities")
	checker(vm.InterruptShadow, "interrupt shadows")
	checker(vm.Trap, "hypervisor interception")
	checker(vm.KVMInterception, "KVM interception")
	checker(vm.SingleStep, "single step behavior")
	checker(vm.EIPOverflow, "instructions in compat mode")
	checker(vm.SVMExceptions, "SVM exceptions")
	checker(vm.CGroup, "cgroup namespace")
	checker(vm.MeasuredBoot, "measured boot logs")
	checker(vm.TPM, "TPM")
	checker(vm.HypervisorHook, "EPT/NPT hooking")
	checker(vm.VCPUScheduling, "vCPU scheduling")
	checker(vm.Emulation, "instruction emulation")
	checker(vm.Timer, "timing anomalies")

	t2 := time.Now()
	v := vm.NewVMAware(vm.Multiple, highThreshArg, allArg, dynamicArg)

	var summary []string

	brand := v.Brand
	isRed := brand == vm.BrandEnumToString(vm.BrandNullBrand) || brand == vm.BrandEnumToString(vm.BrandHyperVRoot)
	brandColor := green
	if isRed {
		brandColor = red
	}
	summary = append(summary, boldStr+"VM brand: "+ansiExit+brandColor+brand+ansiExit)

	if !isVMBrandMultiple(v.Brand) {
		currentColor := green
		if v.Type == "Unknown" || v.Type == "Host machine" {
			currentColor = red
		}
		summary = append(summary, boldStr+"VM type: "+ansiExit+currentColor+v.Type+ansiExit)
	}

	var percentColor string
	switch {
	case v.Percentage == 0:
		percentColor = red
	case v.Percentage < 25:
		percentColor = redOrange
	case v.Percentage < 50:
		percentColor = orange
	case v.Percentage < 75:
		percentColor = greenOrange
	default:
		percentColor = green
	}
	summary = append(summary, boldStr+"VM likeliness: "+ansiExit+percentColor+strconv.Itoa(int(v.Percentage))+"%"+ansiExit)

	detectionColor := red
	detectionStr := "false"
	if v.IsVM {
		detectionColor = green
		detectionStr = "true"
	}
	summary = append(summary, boldStr+"VM confirmation: "+ansiExit+detectionColor+detectionStr+ansiExit)

	var countColor string
	switch v.DetectedCount {
	case 0:
		countColor = red
	case 1:
		countColor = redOrange
	case 2, 3:
		countColor = orange
	case 4:
		countColor = greenOrange
	default:
		countColor = green
	}
	summary = append(summary, boldStr+"VM detections: "+ansiExit+countColor+strconv.Itoa(int(v.DetectedCount))+"/"+strconv.Itoa(int(v.TechniqueCount))+ansiExit)
	summary = append(summary, "")

	if argBits_.test(argVerbose) {
		summary = append(summary, boldStr+"Unsupported detections: "+ansiExit+strconv.Itoa(int(unsupportedCount)))
		summary = append(summary, boldStr+"Supported detections: "+ansiExit+strconv.Itoa(int(supportedCount)))
		summary = append(summary, boldStr+"No permission detections: "+ansiExit+strconv.Itoa(int(noPermsCount)))
		summary = append(summary, boldStr+"Disabled detections: "+ansiExit+strconv.Itoa(int(disabledCount)))

		elapsed := t2.Sub(t1)
		summary = append(summary, boldStr+"Execution speed: "+ansiExit+strconv.FormatFloat(float64(elapsed)/float64(time.Millisecond), 'f', -1, 64)+"ms")
		summary = append(summary, "")
	}

	if v.Brand != vm.BrandEnumToString(vm.BrandNullBrand) {
		description := getVMDescription(v.Brand)
		if description != "" {
			summary = append(summary, boldStr+underline+"VM description:"+ansiExit)
			summary = append(summary, wrapDescription(description)...)
			summary = append(summary, "")
		}
	}

	isBold := ""
	if v.IsVM {
		isBold = boldStr
	}
	conclusionColor := color(v.Percentage)

	summary = append(summary, boldStr+"===== CONCLUSION: "+ansiExit+isBold+conclusionColor+v.Conclusion+ansiExit+boldStr+" ====="+ansiExit)

	fmt.Println()
	for _, line := range summary {
		fmt.Println(line)
	}
	fmt.Println()

	consolePause()
}

// wrapDescription mirrors general()'s word-wrapping loop exactly: a
// two-threshold algorithm (soft limit 60, only actually breaks once the
// running count reaches 64) rather than a plain greedy wrap, ported
// literally including its "phantom 2-char prefix" behavior right after a
// break (see the C++ side's char_count = it->length() + 1 after inserting
// the "\n" marker, which is never reset to 0).
func wrapDescription(description string) []string {
	tokens := strings.Fields(description)

	charCount := 0
	for i := 0; i < len(tokens); i++ {
		charCount += len(tokens[i]) + 1
		if charCount <= 60 {
			continue
		}
		if charCount-1 >= 60+3 {
			out := make([]string, 0, len(tokens)+1)
			out = append(out, tokens[:i+1]...)
			out = append(out, "\n")
			out = append(out, tokens[i+1:]...)
			tokens = out
			i++ // now pointing at the inserted "\n"
			charCount = len(tokens[i]) + 1
		}
	}

	var joined strings.Builder
	for _, t := range tokens {
		joined.WriteString(t)
		if t != "\n" {
			joined.WriteString(" ")
		}
	}

	return strings.Split(joined.String(), "\n")
}
