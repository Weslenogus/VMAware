//go:build darwin

package vmaware

func isUnsupportedForPlatform(flag EnumFlag) bool {
	return !(uint8(flag) >= MacOSStart && uint8(flag) <= MacOSEnd)
}
