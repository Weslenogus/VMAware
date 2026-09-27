//go:build linux

package vmaware

func isUnsupportedForPlatform(flag EnumFlag) bool {
	return !(uint8(flag) >= LinuxStart && uint8(flag) <= LinuxEnd)
}
