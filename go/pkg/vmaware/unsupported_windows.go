//go:build windows

package vmaware

func isUnsupportedForPlatform(flag EnumFlag) bool {
	return !(uint8(flag) >= WindowsStart && uint8(flag) <= WindowsEnd)
}
