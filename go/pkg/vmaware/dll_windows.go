//go:build windows

package vmaware

// Shared DLL/proc resolution helpers mirroring VM::memory::get_module /
// VM::memory::get_function: every technique that calls an ntdll/tbs/bcrypt
// "native" API resolves it dynamically through here rather than importing it
// statically, exactly like the upstream C++ (which always goes through
// GetModuleHandle/LoadLibraryEx + GetProcAddress).
//
// windows.NewLazySystemDLL loads (or reuses, if already loaded, which ntdll
// and kernel32 always are) the module from System32 on first use; NewProc
// resolves the address lazily and caches it. This is the same
// "documented Microsoft API via lazy DLL + NewProc" pattern used throughout
// this file.

import (
	"golang.org/x/sys/windows"
)

var (
	modNtdll    = windows.NewLazySystemDLL("ntdll.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modSetupapi = windows.NewLazySystemDLL("setupapi.dll")
)

// procOrNil resolves a proc by name, returning nil if the DLL or the
// procedure can't be found (mirrors memory::get_function's per-slot
// nullptr-on-failure behavior instead of panicking).
func procOrNil(mod *windows.LazyDLL, name string) *windows.LazyProc {
	if err := mod.Load(); err != nil {
		return nil
	}
	p := mod.NewProc(name)
	if err := p.Find(); err != nil {
		return nil
	}
	return p
}

// callStdcall invokes a *windows.LazyProc that was already resolved via
// procOrNil, returning 0 if p is nil (mirrors calling through a null
// function pointer check upstream always does before invoking).
func callStdcall(p *windows.LazyProc, args ...uintptr) (uintptr, uintptr, error) {
	if p == nil {
		return 0, 0, windows.ERROR_PROC_NOT_FOUND
	}
	r1, r2, err := p.Call(args...)
	return r1, r2, err
}

// getModuleHandle mirrors GetModuleHandleW(name): x/sys/windows only wraps
// the Ex form, so this is a thin helper over that.
func getModuleHandle(name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	if err := windows.GetModuleHandleEx(0, namePtr, &h); err != nil {
		return 0, err
	}
	return h, nil
}
