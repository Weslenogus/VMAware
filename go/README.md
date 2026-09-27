# VMAware (Go port)

A 1:1 Go port of [VMAware](https://github.com/NotRequiem/VMAware)'s C++ VM/hypervisor
detection engine (`src/vmaware.hpp`) and CLI (`src/cli/`), for native use on
Linux/Windows/macOS, plus two WebAssembly targets with an honestly-scoped
feature set (see [Limitations](#limitations) below).

This is a faithful, mechanical translation of an existing, public, MIT-licensed
detection library — the same category of tool as `systemd-detect-virt`,
`virt-what`, or `al-khaser`. No new detection technique was invented for this
port; every technique here does the same check, against the same file paths,
registry keys, CPUID leaves, or command output, as the upstream C++.

## Layout

```
go/
  pkg/vmaware/        the engine: enums, brand table, scoring/merge logic,
                       and every ported technique (grouped by build tag)
  pkg/vmaware/cpuprobe/  a small, self-contained CPUID wrapper (one asm
                       instruction, no code injection) used for exact
                       leaf-level fidelity (brand strings, hypervisor vendor
                       IDs) that a higher-level CPUID library would parse
                       differently than the C++ source does
  cmd/vmaware/        the CLI (1:1 port of src/cli)
  wasm/browser/        browser-facing WASM binding (pure scoring engine only,
                       see Limitations)
```

Within `pkg/vmaware`, technique files are split by build tag to mirror the
`#if VMAWARE_WINDOWS / VMAWARE_LINUX / VMAWARE_APPLE` guards in the C++
source: `techniques_common.go` (no tag, cross-platform CPUID-based checks),
`techniques_linux.go` (`//go:build linux`), the Windows and Darwin
equivalents, and `stubs_unsupported.go` (see below).

## Building

Native, for the OS you're on:

```sh
go build ./...
go build -o vmaware ./cmd/vmaware
```

Cross-compiling (type-checks; only genuinely testable by running the result
on that OS):

```sh
GOOS=windows GOARCH=amd64 go build ./...
GOOS=darwin  GOARCH=arm64 go build ./...
```

WASI (compiles and runs cleanly — see Limitations for what this actually
reports):

```sh
GOOS=wasip1 GOARCH=wasm go build -o vmaware.wasm ./cmd/vmaware
# with a pure-Go WASI runtime (github.com/tetratelabs/wazero/cmd/wazero):
wazero run -mount /proc:/proc -mount /sys:/sys vmaware.wasm -b
```

Browser (pure scoring engine, see Limitations):

```sh
GOOS=js GOARCH=wasm go build -o vmaware.wasm ./wasm/browser
# pair with Go's own wasm_exec.js glue: $(go env GOROOT)/lib/wasm/wasm_exec.js
```

## Limitations

**WebAssembly cannot execute most of what this library does, on any
runtime.** This isn't a policy choice — WASM (browser or WASI) has no CPUID
instruction, no MSR access, no registry, no arbitrary syscalls, and no
ability to run injected native code. That's true independent of language or
library choice.

- **`GOOS=wasip1` (WASI)**: builds and runs cleanly (verified with
  `wazero`), but reports close to nothing. This mirrors the upstream C++
  exactly, not a Go-specific gap: `techniques_linux.go` and friends are
  gated by `//go:build linux`, the literal equivalent of the source's `#if
  VMAWARE_LINUX` — WASI was never a platform branch in the original either,
  so there is no "Linux-ish" fallback to fall into, by design. Only the
  cross-platform CPUID-based techniques even attempt to run, and correctly
  report false (WASM has no CPUID instruction, full stop). If you want the
  file/proc/sysfs checks to run under WASI, that would be new platform
  support beyond what upstream defines — deliberately left out rather than
  invented.
- **`GOOS=js` (browser)**: there is no filesystem, no CPUID, nothing to
  probe at all. Rather than fake it, `wasm/browser` exposes a narrower,
  genuinely useful thing: VMAware's *scoring, brand-merge, and wording*
  logic (`pkg/vmaware/external.go`'s `EvaluateExternal`) as a pure function
  a JS host can call with technique results it obtained some other way. It
  is not "VM detection in the browser" — it's reusing this project's exact
  merge rules and conclusion wording from JS.

**Nine Windows-only techniques are permanently stubbed** (`return false`,
documented in `pkg/vmaware/stubs_unsupported.go`): `TRAP`, `UD`,
`INTERRUPT_SHADOW`, `DBVM`, `SINGLE_STEP`, `EIP_OVERFLOW`, `SVM_EXCEPTIONS`,
`KVM_INTERCEPTION`, `EMULATION`. Upstream implements these by assembling raw
x86 machine code into an executable page and running it, to single-step or
fault the CPU and inspect how a hypervisor mis-emulates the trap. Porting
that faithfully means writing a machine-code assembler/injector, which is a
different (and far riskier) kind of software than the rest of this port, and
it's moot for WASM either way (no CPUID, no hardware breakpoints, no native
code execution). Rather than guess at a byte-for-byte reimplementation that
can't be verified against the original, these are left as honest stubs.

**Two sub-checks are left out of otherwise-ported Windows techniques**,
documented inline where they're skipped: `HYPERVISOR_HOOK`'s Dr0/Dr7
hardware-breakpoint sub-check (`techniques_windows_hook.go`) and
`CPU_HEURISTIC`'s AVX-512/EVEX probe (`techniques_windows_cpu.go`). Both
need machine code this port can't validate without real Windows hardware —
and getting a live debug-register offset wrong doesn't just misdetect, it
can leave a stray hardware breakpoint armed on the thread for the rest of
the process's life. The rest of each technique (the PE double-breakpoint
patch/verify and boundary-straddling-NOP checks in `HYPERVISOR_HOOK`;
AES-NI/AVX/AVX2/CLZERO and the AMD/Intel chipset cross-checks in
`CPU_HEURISTIC`) is fully ported.

**`--rich`** (the Windows TUI, `src/cli/windows_tui.hpp`) is not
implemented; the CLI accepts the flag and falls back to plain output with a
note.

**`TIMER` is a stub on every platform, including Windows.** Off Windows
that's not a scope cut at all: upstream's `timer()` is entirely gated
behind `#if (VMAWARE_X86 && VMAWARE_WINDOWS)` with a plain unconditional
`return false;` for everything else, so non-Windows was already a 1:1 stub
in the original C++. On Windows, upstream's version ORs together a
CPUID-vs-reference-clock race on a priority-boosted, affinity-pinned thread
and a trap-flag/SEH-latency probe — the same kind of raw fault-timing this
port already declines to fake for the nine techniques above, and the
CPUID-race half additionally needs hard real-time guarantees (locked
memory, busy-spin timing) Go's GC/scheduler can't reliably provide. Ported
as an honest stub there too rather than a guess that can't be verified
without a Windows box to test against.

Everything else — CPUID-based cross-platform checks, the full Linux
file/proc/sysfs/dmidecode/cgroup set, Windows registry/SetupAPI/ACPI/TBS.dll
checks, macOS sysctl/IOKit/`ioreg` checks, the brand-merge and scoring
engine, and the CLI — is a real, functional port, verified end-to-end
against real hardware where the container running this port could (this
container itself runs under KVM, and the engine correctly reports so with
100% confidence).

## Attribution

Original library: https://github.com/NotRequiem/VMAware, MIT licensed. This
Go port carries the same license (see `../LICENSE`).
