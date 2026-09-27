//go:build !linux && !darwin && !windows

package main

func isAdmin() bool {
	return false
}
