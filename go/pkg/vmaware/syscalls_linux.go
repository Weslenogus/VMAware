//go:build linux

package vmaware

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// isExecutablePath mirrors the access(path, X_OK) == 0 check findExecutable
// uses. Real executable-bit semantics only matter on the platform that can
// actually exec() the result afterward (dmidecode()/dmesg() both shell out
// via sysResult); see syscalls_wasip1.go for the degraded equivalent.
func isExecutablePath(p string) bool {
	return unix.Access(p, unix.X_OK) == nil
}

// kmsgReadAvailable mirrors kmsg()'s non-blocking /dev/kmsg drain loop
// exactly as vmaware.hpp implements it: open O_NONBLOCK, keep reading until
// 10 consecutive empty/EAGAIN reads in a row (with a short sleep between
// each), then return whatever was collected.
func kmsgReadAvailable() string {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return ""
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
				return sb.String()
			}
			time.Sleep(10 * time.Millisecond)
		case rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK:
			emptyReads++
			if emptyReads >= maxEmptyReads {
				return sb.String()
			}
			time.Sleep(10 * time.Millisecond)
		default:
			return sb.String()
		}
	}
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
