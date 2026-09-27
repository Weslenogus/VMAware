//go:build linux || darwin

package main

import "syscall"

// isAdmin mirrors output.cpp's is_admin() for CLI_LINUX || CLI_APPLE: true if
// the real and effective UID differ (setuid) or the effective UID is root.
func isAdmin() bool {
	uid := syscall.Getuid()
	euid := syscall.Geteuid()
	return uid != euid || euid == 0
}
