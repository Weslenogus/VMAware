//go:build windows && 386

package vmaware

func vpcInvalidTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	var rc bool
	guardedVPCInvalid(func() {
		rc = vpcInvalidProbe() != 0
	})

	if rc {
		return Add(BrandVPC)
	}
	return false
}

func vmwareStrTechnique() bool {
	if isX86ProcessOnARM() {
		return false
	}

	tr := strProbe()
	if tr == 0x4000 {
		return Add(BrandVMWARE)
	}
	return false
}
