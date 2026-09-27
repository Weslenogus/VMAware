//go:build windows && 386

package vmaware

// systemRegistersSLDT mirrors system_registers()'s SLDT technique
// (VMAWARE_X86_32 only): pre-seed a 4-byte sentinel, store the LDTR
// selector into its low 2 bytes, and check whether either the low bytes
// changed or the combined 32-bit value no longer matches the sentinel.
func systemRegistersSLDT() bool {
	buf := []byte{0xEF, 0xBE, 0xAD, 0xDE}
	faulted := guardedAbortCall(func() { sldtProbe(&buf[0]) })
	if faulted {
		return false
	}

	ldtVal := le32(buf)
	found := false
	if buf[0] != 0x00 || buf[1] != 0x00 {
		found = true
	}
	if ldtVal != 0xDEAD0000 {
		found = true
	}
	return found
}

// systemRegistersSMSW mirrors system_registers()'s SMSW technique
// (VMAWARE_X86_32 only): SMSW only ever updates the low 16 bits of a
// 32-bit destination on real hardware, so a 0xCCCCCCCC sentinel should come
// back with its high 16 bits untouched.
func systemRegistersSMSW() bool {
	var result uint32
	faulted := guardedAbortCall(func() { result = smswProbe() })
	if faulted {
		return false
	}
	return ((result>>24)&0xFF == 0xCC) && ((result>>16)&0xFF == 0xCC)
}
