//go:build windows

package main

import "golang.org/x/sys/windows"

// isAdmin mirrors output.cpp's is_admin() for CLI_WINDOWS: whether the
// current process token is elevated.
func isAdmin() bool {
	token := windows.GetCurrentProcessToken()
	var elevated bool
	elevated = token.IsElevated()
	return elevated
}
