//go:build wasip1

package vmaware

import (
	"os"
	"strings"
	"time"
)

// isExecutablePath is the wasip1 stand-in for the Linux build's
// access(path, X_OK) check (syscalls_linux.go): golang.org/x/sys/unix's
// Access doesn't exist for wasip1, and it wouldn't matter anyway --
// dmidecode()/dmesg() (the only callers, via findExecutable) shell out
// through sysResult, and WASI has no process-spawn capability at all, so
// they already degrade to "not detected" regardless of this check's
// precision. A plain existence check is close enough.
func isExecutablePath(p string) bool {
	return pathExists(p)
}

// kmsgReadAvailable is the wasip1 equivalent of the Linux build's raw
// O_NONBLOCK read loop (syscalls_linux.go), built entirely on the standard
// library: golang.org/x/sys/unix's raw Open/Read/Close and the EAGAIN
// constant don't exist for wasip1, but os.File.SetReadDeadline works (WASI
// preview 1 exposes this via poll_oneoff), giving the same "don't block
// forever waiting for the next kernel log line" behavior.
func kmsgReadAvailable() string {
	f, err := os.OpenFile("/dev/kmsg", os.O_RDONLY, 0)
	if err != nil {
		return ""
	}
	defer f.Close()

	var sb strings.Builder
	emptyReads := 0
	const maxEmptyReads = 10
	buf := make([]byte, 1024)

	for {
		_ = f.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, rerr := f.Read(buf)

		if n > 0 {
			sb.Write(buf[:n])
			emptyReads = 0
			if rerr != nil {
				return sb.String()
			}
			continue
		}

		if rerr == nil || os.IsTimeout(rerr) {
			emptyReads++
			if emptyReads >= maxEmptyReads {
				return sb.String()
			}
			continue
		}

		return sb.String()
	}
}

// wslReadProcNonblock is the wasip1 equivalent of the Linux build's raw
// O_NONBLOCK single read (syscalls_linux.go).
func wslReadProcNonblock(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return ""
	}
	defer f.Close()

	_ = f.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if n <= 0 || (err != nil && !os.IsTimeout(err)) {
		return ""
	}
	return string(buf[:n])
}
