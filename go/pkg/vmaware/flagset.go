package vmaware

// FlagSet mirrors VM::flagset (a std::bitset<enum_size+1>). It is a fixed-size
// array so that, like std::bitset, assigning or passing one by value copies
// it rather than aliasing it — the same value semantics the C++ core relies
// on when it snapshots/restores the brand scoreboard.
type FlagSet [NumFlags]bool

// Test reports whether bit is set. Mirrors std::bitset::test, but never
// panics on an out-of-range bit (mirrors the many manual bounds checks the
// C++ code does before calling .test()/.set()).
func (f FlagSet) Test(bit uint8) bool {
	if int(bit) >= len(f) {
		return false
	}
	return f[bit]
}

// Set sets bit to true.
func (f *FlagSet) Set(bit uint8) {
	if int(bit) < len(f) {
		f[bit] = true
	}
}

// SetValue sets bit to the given value.
func (f *FlagSet) SetValue(bit uint8, value bool) {
	if int(bit) < len(f) {
		f[bit] = value
	}
}

// Reset clears bit to false.
func (f *FlagSet) Reset(bit uint8) {
	if int(bit) < len(f) {
		f[bit] = false
	}
}

// SetAll sets every bit (mirrors std::bitset::set()).
func (f *FlagSet) SetAll() {
	for i := range f {
		f[i] = true
	}
}

// ResetAll clears every bit (mirrors std::bitset::reset()).
func (f *FlagSet) ResetAll() {
	for i := range f {
		f[i] = false
	}
}

// Or mirrors flagset |= other.
func (f *FlagSet) Or(other FlagSet) {
	for i := range f {
		if other[i] {
			f[i] = true
		}
	}
}

// AndNot mirrors flagset &= ~other.
func (f *FlagSet) AndNot(other FlagSet) {
	for i := range f {
		if other[i] {
			f[i] = false
		}
	}
}

// And mirrors flagset & other, returning a new FlagSet.
func (f FlagSet) And(other FlagSet) FlagSet {
	var out FlagSet
	for i := range f {
		out[i] = f[i] && other[i]
	}
	return out
}

// None reports whether every bit is false.
func (f FlagSet) None() bool {
	for _, b := range f {
		if b {
			return false
		}
	}
	return true
}

// Any reports whether at least one bit is true.
func (f FlagSet) Any() bool {
	return !f.None()
}

// DisabledTechniques mirrors VM::disabled_techniques: techniques disabled
// permanently at the library level (empty by default, populated by DISABLE()).
var DisabledTechniques []EnumFlag
