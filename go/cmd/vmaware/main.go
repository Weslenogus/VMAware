// Command vmaware is a 1:1 Go port of src/cli (main.cpp/output.cpp/
// wagner_fischer.cpp) from the VMAware C++ project. See pkg/vmaware for the
// ported detection engine itself.
package main

import (
	"fmt"
	"os"
	"strconv"
)

const (
	cliVersion = "2.8.2"
	cliDate    = "September 2026"
)

func help() {
	fmt.Print(`Usage:
 vmaware [option] [extra]
 (do not run with any options if you want the full summary)

Options:
 -h | --help        prints this help menu
 -v | --version     print CLI version and other details
 -a | --all         run the result with ALL the techniques shown and enabled
 -d | --detect      returns the result as a boolean (1 = VM, 0 = bare metal)
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = bare metal)
 -b | --brand       returns the VM brand string
 -l | --brand-list  returns all the possible VM brand string values
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
 -n | --number      returns the number of VM detection techniques it performs
 -t | --type        returns the VM type (if a VM was found)
 -o | --output      set the output path

Extra:
 --disable-notes    no notes will be provided
 --high-threshold   a higher threshold bar for a VM detection will be applied (2x higher)
 --no-ansi          removes color and ansi escape codes from the output
 --dynamic          allow the conclusion message to be dynamic (8 possibilities instead of only 2)
 --experimental     disable experimental techniques
 --verbose          add more information to the output
 --enums            display the technique enum name used by the lib
 --detected-only    only display the techniques that were detected
 --json             output a json-formatted file of the results
 --rich             output the rich TUI alternative of the output (Windows specific; not implemented in this Go port)
`)
	os.Exit(0)
}

func version() {
	fmt.Printf("vmaware v%s (%s)\n\n", cliVersion, cliDate)
	fmt.Print(
		"Derived project of VMAware library at https://github.com/NotRequiem/VMAware\n" +
			"License MIT:<https://opensource.org/license/mit>.\n" +
			"This is free software: you are free to change and redistribute it.\n" +
			"There is NO WARRANTY, to the extent permitted by law.\n" +
			"Developed and maintained by Requiem,\n" +
			"For any inquiries, contact us on Discord at shenzken, or email us at vmaware.support@gmail.com\n" +
			"\nThis Go port: https://github.com/weslenogus/vmaware\n",
	)
	os.Exit(0)
}

func brandListCmd() {
	fmt.Print(`VirtualBox
        VMware
        VMware Express
        VMware ESX
        VMware GSX
        VMware Workstation
        VMware Fusion
        bhyve
        QEMU
        KVM
        KVM Hyper-V Enlightenment
        QEMU+KVM Hyper-V Enlightenment
        QEMU+KVM
        Virtual PC
        Microsoft Hyper-V
        Microsoft Virtual PC/Hyper-V
        Parallels
        Xen HVM
        ACRN
        QNX hypervisor
        Hybrid Analysis
        Sandboxie
        Docker
        Wine
        Anubis
        JoeBox
        ThreatExpert
        CWSandbox
        Comodo
        Bochs
        Lockheed Martin LMHS
        NVMM
        OpenBSD VMM
        Intel HAXM
        Unisys s-Par
        Cuckoo
        BlueStacks
        Jailhouse
        Apple VZ
        Intel KGT (Trusty)
        Microsoft Azure Hyper-V
        Xbox NanoVisor (Hyper-V)
        SimpleVisor
        Hyper-V artifact (host with Hyper-V enabled)
        User-mode Linux
        IBM PowerVM
        Google Compute Engine (KVM)
        OpenStack (KVM)
        KubeVirt (KVM)
        AWS Nitro System (KVM-based)
        Podman
        WSL
        OpenVZ
        ANY.RUN
        Barevisor
        HyperPlatform
        MiniVisor
        Intel TDX
        LKVM
        AMD SEV
        AMD SEV-ES
        AMD SEV-SNP
        Neko Project II
        NoirVisor
        Qihoo 360 Sandbox
        DBVM
        UTM
        Compaq FX!32
        Insignia RealPC
        Connectix Virtual PC
        Containerd
        `)
	os.Exit(0)
}

var argTable = []argTableEntry{
	{"-h", argHelp},
	{"-v", argVersion},
	{"-a", argAll},
	{"-d", argDetect},
	{"-s", argStdout},
	{"-b", argBrand},
	{"-p", argPercent},
	{"-c", argConclusion},
	{"-l", argBrandList},
	{"-n", argNumber},
	{"-t", argType},
	{"-o", argOutput},
	{"help", argHelp},
	{"--help", argHelp},
	{"--version", argVersion},
	{"--all", argAll},
	{"--detect", argDetect},
	{"--stdout", argStdout},
	{"--brand", argBrand},
	{"--percent", argPercent},
	{"--conclusion", argConclusion},
	{"--brand-list", argBrandList},
	{"--number", argNumber},
	{"--type", argType},
	{"--disable-notes", argNotes},
	{"--high-threshold", argHighThreshold},
	{"--dynamic", argDynamic},
	{"--experimental", argExperimental},
	{"--verbose", argVerbose},
	{"--enums", argEnums},
	{"--no-ansi", argNoAnsi},
	{"--detected-only", argDetectedOnly},
	{"--json", argJSON},
	{"--output", argOutput},
	{"--rich", argRich},
}

func findArg(name string) (argTableEntry, bool) {
	for _, e := range argTable {
		if e.Name == name {
			return e, true
		}
	}
	return argTableEntry{}, false
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		general(false, false, false, "")
		return
	}

	var potentialNullArg string
	potentialOutputArg := "results.json"
	generalOutputArg := ""
	collectingDisable := false

	for i := 0; i < len(args); i++ {
		argString := args[i]

		if collectingDisable && len(argString) > 0 && argString[0] == '-' {
			collectingDisable = false
		}

		if collectingDisable {
			if !parseDisableToken(argString) {
				os.Exit(1)
			}
			continue
		}

		if argString == "--disable" {
			collectingDisable = true
			continue
		}

		entry, found := findArg(argString)
		if !found {
			if argBits_.test(argOutput) {
				if f, err := os.Create(argString); err == nil {
					f.Close()
					potentialOutputArg = argString
					generalOutputArg = argString
				}
				argBits_.setValue(argOutput, false)
			} else {
				argBits_.set(argNullArg)
				potentialNullArg = argString
			}
		} else {
			argBits_.set(entry.Flag)
		}
	}

	if argBits_.test(argNullArg) {
		fmt.Fprintf(os.Stderr, "Unknown argument \"%s\", aborting\n", potentialNullArg)
		manageOutput(suggest(potentialNullArg, argTable))
		os.Exit(1)
	}

	if argBits_.test(argHelp) {
		help()
	}

	if argBits_.test(argVersion) {
		version()
	}

	if argBits_.test(argBrandList) {
		brandListCmd()
	}

	if argBits_.test(argNumber) {
		fmt.Println(getTechniqueCount())
		return
	}

	if argBits_.test(argJSON) {
		generateJSON(potentialOutputArg)
		return
	}

	returners := 0
	for _, f := range []argFlag{argStdout, argPercent, argDetect, argBrand, argType, argConclusion} {
		if argBits_.test(f) {
			returners++
		}
	}

	highThreshold := argBits_.test(argHighThreshold)
	all := argBits_.test(argAll)
	dynamic := argBits_.test(argDynamic)

	if returners > 0 {
		if returners > 1 {
			fmt.Fprintln(os.Stderr, "--stdout, --percent, --detect, --brand, --type, and --conclusion must NOT be a combination, choose only a single one")
			os.Exit(1)
		}

		switch {
		case argBits_.test(argStdout):
			os.Exit(runStdout(highThreshold, all, dynamic))
		case argBits_.test(argPercent):
			fmt.Println(runPercent(highThreshold, all, dynamic))
			return
		case argBits_.test(argDetect):
			v := 0
			if runDetect(highThreshold, all, dynamic) {
				v = 1
			}
			fmt.Println(strconv.Itoa(v))
			return
		case argBits_.test(argBrand):
			fmt.Println(runBrand(highThreshold, all, dynamic))
			return
		case argBits_.test(argType):
			fmt.Println(runType(highThreshold, all, dynamic))
			return
		case argBits_.test(argConclusion):
			fmt.Println(runConclusion(highThreshold, all, dynamic))
			return
		}
	}

	general(highThreshold, all, dynamic, generalOutputArg)
}
