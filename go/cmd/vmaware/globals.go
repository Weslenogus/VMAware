package main

// argFlag mirrors globals.hpp's arg_enum.
type argFlag uint8

const (
	argHelp argFlag = iota
	argVersion
	argAll
	argDetect
	argStdout
	argBrand
	argBrandList
	argPercent
	argConclusion
	argNumber
	argType
	argOutput
	argNotes
	argHighThreshold
	argNoAnsi
	argDynamic
	argVerbose
	argEnums
	argDetectedOnly
	argJSON
	argRich
	argExperimental
	argNullArg
)

const argBits = int(argNullArg) + 1

// argBitset mirrors globals.hpp's std::bitset<arg_bits> arg_bitset.
type argBitset [argBits]bool

func (b *argBitset) set(f argFlag)              { b[f] = true }
func (b *argBitset) setValue(f argFlag, v bool) { b[f] = v }
func (b argBitset) test(f argFlag) bool         { return b[f] }

var argBits_ argBitset // the running CLI argument bitset (mirrors the global arg_bitset)

// argTableEntry mirrors arg_table's std::pair<const char*, arg_enum>.
type argTableEntry struct {
	Name string
	Flag argFlag
}

// ANSI color codes, mirroring globals.cpp exactly.
var (
	dim         = "\x1B[38;2;120;120;120m"
	bright      = "\x1B[38;2;180;180;180m"
	boldStr     = "\x1B[1;97m"
	underline   = "\x1B[4m"
	ansiExit    = "\x1B[0m"
	red         = "\x1B[38;2;239;75;75m"
	orange      = "\x1B[38;2;255;180;5m"
	green       = "\x1B[38;2;94;214;114m"
	redOrange   = "\x1B[38;2;247;127;40m"
	greenOrange = "\x1B[38;2;174;197;59m"
	grey        = "\x1B[38;2;108;108;108m"
	white       = "\x1B[38;2;255;255;255m"
)

var (
	unsupportedCount uint32
	supportedCount   uint32
	noPermsCount     uint32
	disabledCount    uint32
)

var (
	tagDetected    = boldStr + "[" + green + "  DETECTED  " + boldStr + "]" + ansiExit
	tagNotDetected = "[" + red + "NOT DETECTED" + ansiExit + "]"
	tagSkipped     = "[" + grey + "  DISABLED  " + ansiExit + "]"
	tagNoPerms     = "[" + grey + "  NO PERMS  " + ansiExit + "]"
	tagNotes       = "[    NOTE    ]"
)
