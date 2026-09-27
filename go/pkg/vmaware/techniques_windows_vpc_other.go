//go:build windows && !386 && !amd64

package vmaware

// Every other Windows architecture (e.g. arm64): both techniques are
// x86-only upstream, so they always return false, same as amd64.

func vpcInvalidTechnique() bool { return false }
func vmwareStrTechnique() bool  { return false }
