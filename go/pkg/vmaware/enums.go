// Package vmaware is a 1:1 Go port of the VMAware C++ header (src/vmaware.hpp)
// from https://github.com/NotRequiem/VMAware (MIT licensed).
//
// Scope note: a handful of C++ techniques (TRAP, UD, INTERRUPT_SHADOW, DBVM,
// SINGLE_STEP, EIP_OVERFLOW, SVM_EXCEPTIONS) work by injecting raw machine
// code into executable memory to single-step or trap the CPU. Those are not
// portable to Go (or to WebAssembly, which has no such capability at all)
// without re-implementing a machine-code injector, so they are intentionally
// left as documented, always-false stubs in stubs_unsupported.go rather than
// being guessed at. Every other technique is a faithful, functional port.
package vmaware

// EnumFlag mirrors VM::enum_flags from vmaware.hpp. The ordering is load-bearing:
// it must stay identical to the C++ enum so that FlagSet bit positions, the
// Windows/Linux/macOS range constants below, and technique registration all
// line up with the upstream source (used only to keep the two implementations
// easy to diff against each other; nothing here depends on the C++ ABI).
type EnumFlag uint8

const (
	// Windows
	GPUCapabilities EnumFlag = iota
	ACPISignature
	PowerCapabilities
	Drivers
	Handles
	VirtualProcessors
	Display
	DLL
	Wine
	VirtualRegistry
	Mutex
	VPCInvalid
	VMwareStr
	Gamarue
	Cuckoo
	Trap
	UD
	InterruptShadow
	DBVM
	KernelObjects
	NVRAM
	CPUHeuristic
	MSR
	KVMInterception
	HypervisorHook
	SingleStep
	EIPOverflow
	SVMExceptions
	MeasuredBoot
	TPM
	VCPUScheduling
	Emulation

	// Linux and Windows
	SystemRegisters
	Firmware
	Devices
	Azure
	BootLogo
	Disk

	// Linux
	SMBIOSVMBit
	KMSG
	CVendor
	QEMUFwCfg
	Systemd
	CType
	DockerEnv
	Dmidecode
	Dmesg
	HWMon
	LinuxUserHost
	QEMUVirtualDMI
	QEMUUSB
	HypervisorDir
	UMLCPU
	VBoxModule
	SysinfoProc
	DMIScan
	PodmanFile
	WSLProc
	FileAccessHistory
	MAC
	ContainerPID
	BluestacksFolders
	AMDSevMSR
	Temperature
	CGroup
	Processes

	// Linux and macOS
	ThreadCount

	// macOS
	MacMemsize
	MacIOKit
	MacSIP
	IORegGrep
	HWModel
	MacSys

	// Cross-platform
	HypervisorBit
	VMID
	ThreadMismatch
	Timer
	CPUBrand
	HypervisorStr
	CPUIDSignature
	BochsCPU
	KGTSignature

	// Special flags, different from settings.
	Default
	All
	NullArg // does nothing, placeholder flag mainly for the CLI

	// Start of settings technique flags (ordering is load-bearing).
	HighThreshold
	Experimental
	Dynamic
	Multiple
)

// BrandEnum mirrors VM::brand_enum.
type BrandEnum uint8

const (
	BrandVBOX BrandEnum = iota
	BrandVMWARE
	BrandVMWAREExpress
	BrandVMWAREESX
	BrandVMWAREGSX
	BrandVMWAREWorkstation
	BrandVMWAREFusion
	BrandVMWAREHard
	BrandBHYVE
	BrandKVM
	BrandQEMU
	BrandQEMUKVM
	BrandKVMHyperV
	BrandQEMUKVMHyperV
	BrandHyperV
	BrandHyperVVPC
	BrandParallels
	BrandXen
	BrandACRN
	BrandQNX
	BrandHybrid
	BrandSandboxie
	BrandDocker
	BrandWine
	BrandVPC
	BrandAnubis
	BrandJoebox
	BrandThreatExpert
	BrandCWSandbox
	BrandComodo
	BrandBochs
	BrandNVMM
	BrandBSDVMM
	BrandIntelHAXM
	BrandUnisys
	BrandLMHS
	BrandCuckoo
	BrandBluestacks
	BrandJailhouse
	BrandAppleVZ
	BrandIntelKGT
	BrandAzureHyperV
	BrandSimpleVisor
	BrandHyperVRoot
	BrandUML
	BrandPowerVM
	BrandGCE
	BrandOpenStack
	BrandKubeVirt
	BrandAWSNitro
	BrandPodman
	BrandWSL
	BrandOpenVZ
	BrandBarevisor
	BrandHyperPlatform
	BrandMiniVisor
	BrandIntelTDX
	BrandLKVM
	BrandAMDSev
	BrandAMDSevES
	BrandAMDSevSNP
	BrandNekoProject
	BrandNoirVisor
	BrandQihoo
	BrandDBVM
	BrandUTM
	BrandCompaq
	BrandInsignia
	BrandConnectix
	BrandContainerd
	// Do not move BrandNullBrand: it is used to count the number of brands.
	BrandNullBrand
)

// HyperXState mirrors VM::hyperx_state.
type HyperXState uint8

const (
	HyperVUnknown HyperXState = iota
	HyperVHost
	HyperVRealVM
	HyperVNestedVM
	HyperVEnlightenment
	HyperVSpoofed
)

// Boundary constants, computed exactly like the C++ static constexpr values.
const (
	EnumSize            = uint8(Multiple) // last element of EnumFlag
	BaseTechniqueCount  = uint16(HighThreshold)
	ThresholdScore      = uint16(150)
	HighThresholdScore  = uint16(300)
	Shortcut            = true
	MaxCustomTechniques = 256
	MaxBrands           = uint16(BrandNullBrand) + 1

	EnumBegin      = uint8(0)
	EnumEnd        = EnumSize + 1
	TechniqueBegin = EnumBegin
	TechniqueEnd   = uint8(Default)
	SettingsBegin  = uint8(Default)
	SettingsEnd    = EnumEnd

	WindowsStart = uint8(GPUCapabilities)
	WindowsEnd   = uint8(Disk)
	LinuxStart   = uint8(SystemRegisters)
	LinuxEnd     = uint8(ThreadCount)
	MacOSStart   = uint8(ThreadCount)
	MacOSEnd     = uint8(MacSys)

	// NumFlags is the fixed width of a FlagSet (equivalent to std::bitset<enum_size+1>).
	NumFlags = int(EnumEnd)
)

// ExperimentalTechniques mirrors VM::experimental_techniques.
var ExperimentalTechniques = [2]EnumFlag{VCPUScheduling, Emulation}
