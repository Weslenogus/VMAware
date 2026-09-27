package vmaware

import (
	"math/bits"
	"os"
	"strings"
)

// readFile mirrors VM::util::read_file: returns "" (not an error) when the
// path doesn't exist, expands a leading "~" to $HOME, and otherwise returns
// the whole file with a trailing newline on every line (matching the
// line-by-line std::getline + "\n" reassembly upstream does).
func readFile(rawPath string) string {
	path := rawPath
	if strings.HasPrefix(rawPath, "~") {
		if home := os.Getenv("HOME"); home != "" {
			path = home + rawPath[1:]
		}
	}

	if !pathExists(path) {
		return ""
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// pathExists mirrors VM::util::exists.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isDirectory mirrors VM::util::is_directory.
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// readFileBinary mirrors VM::util::read_file_binary, including the 16MiB
// safety cap upstream enforces.
func readFileBinary(path string) []byte {
	const maxSafeSize = 16 * 1024 * 1024
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(data) > maxSafeSize {
		return nil
	}
	return data
}

// popcount mirrors VM::util::popcount, using the standard library's portable
// (and typically hardware-accelerated) implementation instead of a hand
// rolled loop.
func popcount(v uint64) int32 {
	return int32(bits.OnesCount64(v))
}

// isUnsupported mirrors VM::util::is_unsupported: cross-platform techniques
// (HypervisorBit..KGTSignature) are always supported; every other technique
// is only supported on the platform it was written for. The applicable
// platform range is picked at compile time by GOOS-tagged files
// (unsupported_linux.go / unsupported_windows.go / unsupported_darwin.go /
// unsupported_other.go), mirroring the #if VMAWARE_LINUX/.../#else ladder.
func isUnsupported(flag EnumFlag) bool {
	if flag >= HypervisorBit && flag <= KGTSignature {
		return false
	}
	return isUnsupportedForPlatform(flag)
}
