//go:build !windows && !darwin

package vmaware

import (
	"strconv"
	"strings"
)

// firstLine mirrors one std::getline(f, s) call: the text up to (but not
// including) the first '\n' readFile's reassembled output contains, or the
// whole string if there's no newline in it at all (an empty file, which
// readFile represents as "").
func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

// isSMTActive mirrors the #else (non-Windows, non-Apple) branch of
// thread_mismatch()'s is_smt_active lambda (vmaware.hpp lines ~7137-7215):
// try /sys/devices/system/cpu/smt/control, then .../smt/active, then
// cpu0's thread_siblings_list, then finally /proc/cpuinfo's
// siblings-vs-cpu-cores comparison, in that exact order, returning as soon
// as one of them gives a definite answer.
func isSMTActive() bool {
	if s := strings.TrimSpace(firstLine(readFile("/sys/devices/system/cpu/smt/control"))); s != "" {
		switch s {
		case "on":
			return true
		case "off", "forceoff", "notsupported":
			return false
		}
	}

	if s := strings.TrimSpace(firstLine(readFile("/sys/devices/system/cpu/smt/active"))); s != "" {
		switch s {
		case "1":
			return true
		case "0":
			return false
		}
	}

	if s := strings.TrimSpace(firstLine(readFile("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list"))); s != "" {
		for i := 0; i < len(s); i++ {
			if s[i] == ',' || s[i] == '-' {
				return true
			}
		}
	}

	if content := readFile("/proc/cpuinfo"); content != "" {
		siblings := -1
		cores := -1

		for _, line := range strings.Split(content, "\n") {
			if line == "" {
				break
			}

			pos := strings.IndexByte(line, ':')
			if pos < 0 {
				continue
			}

			key := strings.TrimSpace(line[:pos])
			val := strings.TrimSpace(line[pos+1:])

			switch key {
			case "siblings":
				if n, err := strconv.Atoi(val); err == nil {
					siblings = n
				}
			case "cpu cores":
				if n, err := strconv.Atoi(val); err == nil {
					cores = n
				}
			}
		}

		if siblings > cores && siblings > 0 && cores > 0 {
			return true
		}
	}

	return false
}
