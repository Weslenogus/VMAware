//go:build linux

package vmaware

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/weslenogus/vmaware/go/pkg/vmaware/cpuprobe"
)

func init() {
	RegisterTechnique(Systemd, 35, systemdVirt)
	RegisterTechnique(CVendor, 65, chassisVendor)
	RegisterTechnique(CType, 20, chassisType)
	RegisterTechnique(DockerEnv, 100, dockerenv)
	RegisterTechnique(Dmidecode, 55, dmidecode)
	RegisterTechnique(MAC, 20, macAddressCheck)
	RegisterTechnique(Dmesg, 55, dmesg)
	RegisterTechnique(HWMon, 35, hwmon)
	RegisterTechnique(LinuxUserHost, 10, linuxUserHost)
	RegisterTechnique(BluestacksFolders, 5, bluestacks)
	RegisterTechnique(AMDSevMSR, 50, amdSevMSR)
	RegisterTechnique(QEMUVirtualDMI, 40, qemuVirtualDMI)
	RegisterTechnique(QEMUUSB, 20, qemuUSB)
	RegisterTechnique(HypervisorDir, 20, hypervisorDir)
	RegisterTechnique(UMLCPU, 80, umlCPU)
	RegisterTechnique(KMSG, 5, kmsg)
	RegisterTechnique(VBoxModule, 15, vboxModule)
	RegisterTechnique(SysinfoProc, 15, sysinfoProc)
	RegisterTechnique(DMIScan, 50, dmiScan)
	RegisterTechnique(SMBIOSVMBit, 50, smbiosVMBit)
	RegisterTechnique(PodmanFile, 5, podmanFile)
	RegisterTechnique(WSLProc, 30, wslProcSubdir)
	RegisterTechnique(QEMUFwCfg, 70, qemuFwCfg)
	RegisterTechnique(FileAccessHistory, 15, fileAccessHistory)
	RegisterTechnique(ContainerPID, 75, containerProcID)
	RegisterTechnique(Temperature, 20, temperature)
	RegisterTechnique(CGroup, 70, cgroup)
	RegisterTechnique(Processes, 40, processes)
}

// --- small Linux-local helpers (mirroring bits of VM::util / VM::string that
// util.go doesn't already provide) ---

// linuxIsRoot mirrors VM::util::is_admin's Linux/Apple branch (geteuid()==0).
func linuxIsRoot() bool {
	return os.Geteuid() == 0
}

// sysResult mirrors VM::util::sys_result: runs cmd through a shell (like
// popen(cmd, "r")), collects everything the child wrote to stdout, and
// strips a single trailing '\n' if present. Like the Darwin port's copy of
// this same helper, the underlying exec error is ignored on purpose --
// upstream's popen-based version has no separate error channel either, it
// just reads whatever ended up in the pipe before EOF.
func sysResult(cmd string) string {
	out, _ := exec.Command("/bin/sh", "-c", cmd).Output()
	return strings.TrimSuffix(string(out), "\n")
}

// findExecutable mirrors the repeated "find_binary" lambda (access(path,
// X_OK) == 0) used by dmidecode()/dmesg(): returns the first path in the
// list that exists and is executable, or "" if none are.
func findExecutable(paths []string) string {
	for _, p := range paths {
		if unix.Access(p, unix.X_OK) == nil {
			return p
		}
	}
	return ""
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

// linuxIsProcRunning mirrors VM::util::is_proc_running's Linux branch:
// scans /proc/<pid>/cmdline for every numeric /proc entry and compares the
// basename of argv[0] against executable.
func linuxIsProcRunning(executable string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isNumericASCII(name) {
			continue
		}

		data, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil || len(data) == 0 {
			continue
		}

		var argv0 []byte
		if nul := bytes.IndexByte(data, 0); nul >= 0 {
			argv0 = data[:nul]
		} else {
			argv0 = data
		}
		if len(argv0) == 0 {
			continue
		}

		base := string(argv0)
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}

		if base == executable {
			return true
		}
	}

	return false
}

// systemdVirt mirrors VM::systemd_virt (@implements VM::SYSTEMD).
func systemdVirt() bool {
	if !pathExists("/usr/bin/systemd-detect-virt") && !pathExists("/bin/systemd-detect-virt") {
		return false
	}
	return sysResult("systemd-detect-virt") != "none"
}

// chassisVendor mirrors VM::chassis_vendor (@implements VM::CVENDOR).
func chassisVendor() bool {
	const vendorFile = "/sys/devices/virtual/dmi/id/chassis_vendor"
	if !pathExists(vendorFile) {
		return false
	}

	vendor := readFile(vendorFile)
	if strings.Contains(vendor, "QEMU") {
		return Add(BrandQEMU)
	}
	if strings.Contains(vendor, "Oracle Corporation") {
		return Add(BrandVBOX)
	}
	return false
}

// chassisType mirrors VM::chassis_type (@implements VM::CTYPE).
func chassisType() bool {
	const chassis = "/sys/devices/virtual/dmi/id/chassis_type"
	if !pathExists(chassis) {
		return false
	}

	content := readFile(chassis)

	// Mirror std::stoi: skip leading whitespace, take an optional sign and
	// the run of digits that follows, ignoring anything after -- rather than
	// requiring the whole string (readFile's trailing '\n' included) to be
	// numeric.
	i := 0
	for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' ||
		content[i] == '\v' || content[i] == '\f' || content[i] == '\r') {
		i++
	}
	start := i
	if i < len(content) && (content[i] == '+' || content[i] == '-') {
		i++
	}
	digitsStart := i
	for i < len(content) && content[i] >= '0' && content[i] <= '9' {
		i++
	}
	if i == digitsStart {
		return false
	}

	n, err := strconv.Atoi(content[start:i])
	if err != nil {
		return false
	}
	return n == 1
}

// dockerenv mirrors VM::dockerenv (@implements VM::DOCKERENV).
func dockerenv() bool {
	if pathExists("/.dockerenv") || pathExists("/.dockerinit") {
		return Add(BrandDocker)
	}
	return false
}

// dmidecode mirrors VM::dmidecode (@implements VM::DMIDECODE).
func dmidecode() bool {
	if !linuxIsRoot() {
		return false
	}

	dmiBin := findExecutable([]string{
		"/usr/sbin/dmidecode",
		"/sbin/dmidecode",
		"/usr/bin/dmidecode",
		"/bin/dmidecode",
	})
	if dmiBin == "" {
		return false
	}

	output := sysResult(dmiBin + " -t system 2>/dev/null")
	if output == "" {
		return false
	}

	lower := strings.ToLower(output)
	if strings.Contains(lower, "qemu") {
		return Add(BrandQEMU)
	}
	if strings.Contains(lower, "virtualbox") || strings.Contains(lower, "innotek") {
		return Add(BrandVBOX)
	}
	if strings.Contains(lower, "kvm") || strings.Contains(lower, "bochs") {
		return Add(BrandKVM)
	}
	if strings.Contains(lower, "vmware") || strings.Contains(lower, "hyper-v") ||
		strings.Contains(lower, "virtual machine") || strings.Contains(lower, "parallels") {
		return true
	}
	return false
}

// macAddressCheck mirrors VM::mac_address_check (@implements VM::MAC).
//
// Upstream builds this from raw SIOCGIFCONF/SIOCGIFFLAGS/SIOCGIFHWADDR
// ioctls to find the first non-loopback interface's hardware address. Go's
// net.Interfaces() is the standard, idiomatic equivalent of that same
// enumeration (backed by the same kernel interface list), so it's used here
// instead of hand-rolling the ioctls.
func macAddressCheck() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	var mac net.HardwareAddr
	found := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac = iface.HardwareAddr
		found = true
		break
	}

	if !found || len(mac) < 3 {
		return false
	}
	if mac[0] == 0 && mac[1] == 0 && mac[2] == 0 {
		return false
	}

	prefix := uint32(mac[0]) | uint32(mac[1])<<8 | uint32(mac[2])<<16

	const (
		vbox = 0x270008 // 08:00:27
		vmw1 = 0x29000C // 00:0C:29
		vmw2 = 0x141C00 // 00:1C:14
		vmw3 = 0x565000 // 00:50:56
		vmw4 = 0x690500 // 00:05:69
		xen  = 0xE31600 // 00:16:E3
		par  = 0x421C00 // 00:1C:42
	)

	switch prefix {
	case vbox:
		return Add(BrandVBOX)
	case vmw1, vmw2, vmw3, vmw4:
		return Add(BrandVMWARE)
	case xen:
		return Add(BrandXen)
	case par:
		return Add(BrandParallels)
	}
	return false
}

// dmesg mirrors VM::dmesg (@implements VM::DMESG).
func dmesg() bool {
	if !linuxIsRoot() {
		return false
	}

	dmesgBin := findExecutable([]string{
		"/bin/dmesg",
		"/usr/bin/dmesg",
		"/sbin/dmesg",
		"/usr/sbin/dmesg",
	})
	if dmesgBin == "" {
		return false
	}

	output := sysResult(dmesgBin + " 2>/dev/null")
	if output == "" {
		return false
	}

	lower := strings.ToLower(output)

	// Check hypervisor banner lines to avoid false positives on bare-metal
	// hosts where host modules (like kvm_intel / kvm_amd) are loaded.
	if strings.Contains(lower, "hypervisor detected: kvm") ||
		strings.Contains(lower, "booting paravirtualized kernel on kvm") ||
		(strings.Contains(lower, "hypervisor") && strings.Contains(lower, "kvm")) {
		return Add(BrandKVM)
	}
	if strings.Contains(lower, "qemu virtual cpu") || strings.Contains(lower, "dmi: qemu") {
		return Add(BrandQEMU)
	}
	if strings.Contains(lower, "virtualbox") || strings.Contains(lower, "vboxguest") {
		return Add(BrandVBOX)
	}
	if strings.Contains(lower, "hypervisor detected") || strings.Contains(lower, "paravirtualized kernel") {
		return true
	}
	return false
}

// hwmon mirrors VM::hwmon (@implements VM::HWMON).
func hwmon() bool {
	return !pathExists("/sys/class/hwmon/")
}

// linuxUserHost mirrors VM::linux_user_host (@implements VM::LINUX_USER_HOST).
func linuxUserHost() bool {
	if linuxIsRoot() {
		return false
	}

	username, hasUser := os.LookupEnv("USER")
	hostname, hasHost := os.LookupEnv("HOSTNAME")
	if !hasUser || !hasHost {
		return false
	}

	return username == "liveuser" && hostname == "localhost-live"
}

// bluestacks mirrors VM::bluestacks (@implements VM::BLUESTACKS_FOLDERS).
// Upstream gates this entirely behind "#if !VMAWARE_ARM ... #else ...",
// i.e. it's a no-op everywhere except ARM.
func bluestacks() bool {
	if runtime.GOARCH != "arm" && runtime.GOARCH != "arm64" {
		return false
	}

	if pathExists("/mnt/windows/BstSharedFolder") || pathExists("/sdcard/windows/BstSharedFolder") {
		return Add(BrandBluestacks)
	}
	return false
}

// amdSevMSR mirrors VM::amd_sev_msr (@implements VM::AMD_SEV_MSR).
func amdSevMSR() bool {
	if !cpuprobe.IsAMD() {
		return false
	}
	if !linuxIsRoot() {
		return false
	}
	if !cpuprobe.IsLeafSupported(cpuprobe.LeafEncryptedMem) {
		return false
	}

	eax, _, _, _ := cpuprobe.CPUID(cpuprobe.LeafEncryptedMem)
	if eax&(1<<1) == 0 {
		return false
	}

	f, err := os.Open("/dev/cpu/0/msr")
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 8)
	const msrIndex = 0xc0010131
	n, err := f.ReadAt(buf, msrIndex)
	if err != nil || n != 8 {
		return false
	}

	result := binary.LittleEndian.Uint64(buf)
	if result&(uint64(1)<<2) != 0 {
		return Add(BrandAMDSevSNP)
	}
	if result&(uint64(1)<<1) != 0 {
		return Add(BrandAMDSevES)
	}
	if result&1 != 0 {
		return Add(BrandAMDSev)
	}
	return false
}

// qemuVirtualDMI mirrors VM::qemu_virtual_dmi (@implements VM::QEMU_VIRTUAL_DMI).
func qemuVirtualDMI() bool {
	const sysVendor = "/sys/devices/virtual/dmi/id/sys_vendor"
	const modalias = "/sys/devices/virtual/dmi/id/modalias"

	if pathExists(sysVendor) && pathExists(modalias) {
		sv := readFile(sysVendor)
		ma := readFile(modalias)
		if strings.Contains(sv, "QEMU") && strings.Contains(ma, "QEMU") {
			return Add(BrandQEMU)
		}
	}
	return false
}

// qemuUSB mirrors VM::qemu_usb (@implements VM::QEMU_USB).
func qemuUSB() bool {
	if !linuxIsRoot() {
		return false
	}

	content := readFile("/sys/kernel/debug/usb/devices")
	if content == "" {
		return false
	}
	if strings.Contains(content, "QEMU") {
		return Add(BrandQEMU)
	}
	return false
}

// hypervisorDir mirrors VM::hypervisor_dir (@implements VM::HYPERVISOR_DIR).
func hypervisorDir() bool {
	entries, err := os.ReadDir("/sys/hypervisor")
	if err != nil {
		return false
	}
	// os.ReadDir never returns "." / "..", matching the C++ loop's explicit
	// skip of those two entries before counting.
	hasEntries := len(entries) > 0

	typeExists := pathExists("/sys/hypervisor/type")
	if typeExists {
		content := readFile("/sys/hypervisor/type")
		if strings.Contains(content, "xen") {
			return Add(BrandXen)
		}
	}

	return hasEntries && typeExists
}

// umlCPU mirrors VM::uml_cpu (@implements VM::UML_CPU).
func umlCPU() bool {
	if cpuprobe.GetBrand() == "UML" {
		return Add(BrandUML)
	}

	const file = "/proc/cpuinfo"
	if pathExists(file) {
		if strings.Contains(readFile(file), "User Mode Linux") {
			return Add(BrandUML)
		}
	}
	return false
}

// kmsg mirrors VM::kmsg (@implements VM::KMSG).
func kmsg() bool {
	if !linuxIsRoot() {
		return false
	}

	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	var sb strings.Builder
	emptyReads := 0
	const maxEmptyReads = 10
	buf := make([]byte, 1024)

	for {
		n, rerr := unix.Read(fd, buf)
		switch {
		case rerr == nil && n > 0:
			sb.Write(buf[:n])
			emptyReads = 0
		case rerr == nil && n == 0:
			emptyReads++
			if emptyReads >= maxEmptyReads {
				goto done
			}
			time.Sleep(10 * time.Millisecond)
		case rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK:
			emptyReads++
			if emptyReads >= maxEmptyReads {
				goto done
			}
			time.Sleep(10 * time.Millisecond)
		default:
			goto done
		}
	}

done:
	content := sb.String()
	if content == "" {
		return false
	}
	return strings.Contains(content, "Hypervisor detected")
}

// vboxModule mirrors VM::vbox_module (@implements VM::VBOX_MODULE).
func vboxModule() bool {
	const file = "/proc/modules"
	if !pathExists(file) {
		return false
	}
	if strings.Contains(readFile(file), "vboxguest") {
		return Add(BrandVBOX)
	}
	return false
}

// sysinfoProc mirrors VM::sysinfo_proc (@implements VM::SYSINFO_PROC).
func sysinfoProc() bool {
	const file = "/proc/sysinfo"
	if !pathExists(file) {
		return false
	}
	return strings.Contains(readFile(file), "VM00")
}

// dmiScanFiles mirrors the "dmi_array" constexpr array in VM::dmi_scan.
var dmiScanFiles = []string{
	"/sys/class/dmi/id/bios_vendor",
	"/sys/class/dmi/id/board_name",
	"/sys/class/dmi/id/board_vendor",
	"/sys/class/dmi/id/chassis_asset_tag",
	"/sys/class/dmi/id/product_family",
	"/sys/class/dmi/id/product_sku",
	"/sys/class/dmi/id/sys_vendor",
}

// dmiScanTable mirrors the "vm_table" constexpr array in VM::dmi_scan.
var dmiScanTable = []struct {
	needle string
	brand  BrandEnum
}{
	{"kvm", BrandKVM},
	{"openstack", BrandOpenStack},
	{"kubevirt", BrandKubeVirt},
	{"amazon ec2", BrandAWSNitro},
	{"qemu", BrandQEMU},
	{"vmware", BrandVMWARE},
	{"innotek gmbh", BrandVBOX},
	{"virtualbox", BrandVBOX},
	{"oracle corporation", BrandVBOX},
	{"bochs", BrandBochs},
	{"parallels", BrandParallels},
	{"bhyve", BrandBHYVE},
	{"hyper-v", BrandHyperV},
	{"apple virtualization", BrandAppleVZ},
	{"google compute engine", BrandGCE},
}

// dmiScan mirrors VM::dmi_scan (@implements VM::DMI_SCAN).
func dmiScan() bool {
	for _, file := range dmiScanFiles {
		if !pathExists(file) {
			continue
		}
		content := readFile(file)
		if content == "" {
			continue
		}
		content = strings.ToLower(content)

		for _, entry := range dmiScanTable {
			if !strings.Contains(content, entry.needle) {
				continue
			}
			if entry.brand == BrandAWSNitro {
				if smbiosVMBit() {
					return Add(BrandAWSNitro)
				}
				continue
			}
			return Add(entry.brand)
		}
	}
	return false
}

// smbiosVMBit mirrors VM::smbios_vm_bit (@implements VM::SMBIOS_VM_BIT).
func smbiosVMBit() bool {
	if !linuxIsRoot() {
		return false
	}

	const file = "/sys/firmware/dmi/entries/0-0/raw"
	if !pathExists(file) {
		return false
	}

	content := readFileBinary(file)
	if len(content) < 20 || content[1] < 20 {
		return false
	}
	return content[19]&(1<<4) != 0
}

// podmanFile mirrors VM::podman_file (@implements VM::PODMAN_FILE).
func podmanFile() bool {
	if pathExists("/run/.containerenv") {
		return Add(BrandPodman)
	}
	return false
}

// wslReadProcNonblock mirrors the "read_proc_nonblock" lambda in
// VM::wsl_proc_subdir: a single non-blocking read of up to 512 bytes.
func wslReadProcNonblock(path string) string {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(fd)

	buf := make([]byte, 512)
	n, err := unix.Read(fd, buf)
	if err != nil || n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// wslProcSubdir mirrors VM::wsl_proc_subdir (@implements VM::WSL_PROC).
func wslProcSubdir() bool {
	osrelease := wslReadProcNonblock("/proc/sys/kernel/osrelease")
	version := wslReadProcNonblock("/proc/version")
	if osrelease == "" || version == "" {
		return false
	}

	osHit := strings.Contains(osrelease, "WSL") || strings.Contains(osrelease, "Microsoft")
	verHit := strings.Contains(version, "WSL") || strings.Contains(version, "Microsoft")
	if osHit && verHit {
		return Add(BrandWSL)
	}
	return false
}

// qemuFwCfg mirrors VM::qemu_fw_cfg (@implements VM::QEMU_FW_CFG).
func qemuFwCfg() bool {
	// 1) Device Tree-based detection.
	if pathExists("/proc/device-tree/fw-cfg") {
		return Add(BrandQEMU)
	}
	if pathExists("/proc/device-tree/hypervisor/compatible") {
		return Add(BrandQEMU)
	}

	// 2) sysfs-based detection.
	const modulePath = "/sys/module/qemu_fw_cfg/"
	const firmwarePath = "/sys/firmware/qemu_fw_cfg/"
	if isDirectory(modulePath) && pathExists(modulePath) &&
		isDirectory(firmwarePath) && pathExists(firmwarePath) {
		return Add(BrandQEMU)
	}
	return false
}

// fileAccessHistory mirrors VM::file_access_history (@implements VM::FILE_ACCESS_HISTORY).
func fileAccessHistory() bool {
	content := readFile("~/.local/share/recently-used.xbel")
	if content == "" {
		return false
	}
	return strings.Count(content, "href") <= 10
}

// containerProcID mirrors VM::container_proc_id (@implements VM::CONTAINER_PID).
func containerProcID() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	parseNumber := func(line, prefix string) int {
		if !strings.HasPrefix(line, prefix) {
			return -1
		}
		num := 0
		for i := len(prefix); i < len(line); i++ {
			ch := line[i]
			if ch >= '0' && ch <= '9' {
				num = num*10 + int(ch-'0')
			} else if num > 0 {
				break
			}
		}
		return num
	}

	pidMatch := false
	ppidMatch := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if parseNumber(line, "Pid:") == 1 {
			pidMatch = true
		}
		if parseNumber(line, "PPid:") == 0 {
			ppidMatch = true
		}
		if pidMatch && ppidMatch {
			return true
		}
	}
	return false
}

// temperature mirrors VM::temperature (@implements VM::TEMPERATURE).
func temperature() bool {
	if pathExists("/sys/class/thermal/cooling_device0") {
		return false
	}
	return !pathExists("/sys/class/thermal/thermal_zone0/")
}

// cgroup mirrors VM::cgroup (@implements VM::CGROUP).
func cgroup() bool {
	contents := readFile("/proc/self/cgroup")
	if contents == "" {
		return false
	}

	if strings.Contains(contents, "docker") {
		return Add(BrandDocker)
	}
	if strings.Contains(contents, "containerd") {
		return Add(BrandContainerd)
	}

	isHexLower := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
	}

	// Look for a 64-char lowercase hex segment in any path component
	// (cgroup v1).
	for i := 0; i+64 <= len(contents); i++ {
		hexRun := true
		for j := i; j < i+64; j++ {
			if !isHexLower(contents[j]) {
				hexRun = false
				break
			}
		}
		if !hexRun {
			continue
		}

		var after byte
		if i+64 < len(contents) {
			after = contents[i+64]
		}
		if after == '\n' || after == '/' || after == 0 {
			return Add(BrandDocker)
		}
	}

	// Cgroup v2 with cgroup namespace isolation: Docker isolates the cgroup
	// namespace so the unified hierarchy line appears as "0::/" (container
	// sees itself as root).
	pos := 0
	for pos < len(contents) {
		end := strings.IndexByte(contents[pos:], '\n')
		var line string
		if end < 0 {
			line = contents[pos:]
			pos = len(contents)
		} else {
			line = contents[pos : pos+end]
			pos += end + 1
		}

		for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == ' ') {
			line = line[:len(line)-1]
		}

		if line == "0::/" {
			return true
		}
	}

	return false
}

// processes mirrors VM::processes (@implements VM::PROCESSES).
func processes() bool {
	if linuxIsProcRunning("qemu_ga") {
		return Add(BrandQEMU)
	}
	if pathExists("/proc/xen") {
		return Add(BrandXen)
	}
	if pathExists("/proc/vz") {
		return Add(BrandOpenVZ)
	}
	return false
}
