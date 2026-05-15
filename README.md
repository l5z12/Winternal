# Winternal

A Windows ARK (anti-rootkit) toolkit and kernel-research scripting host for
Win11 24H2 (build 26100). Ships:

- a KMDF kernel driver (`Winternal.sys`) exposing kernel R/W, symbol lookup,
  pool alloc/free, kernel function call, process unprotect/kill, force-
  protect via Ob callbacks, EPROCESS field patching (signature level,
  token UIAccess), kernel CODE-page patching, kernel inline hooks, kernel
  process introspection (threads / mem regions / token / mitigations) run
  from kernel context so user-mode hooks can't filter the answer, kernel
  callback/SSDT/driver enumeration, SCM-bypassing driver register/load/
  unload, and an **embedded Lua 5.4 interpreter** that runs scripts at
  PASSIVE_LEVEL inside the driver;
- a CLI (`Winternal.exe`) with subcommands for everything above plus an
  embedded user-mode Lua 5.4 with a `wn.*` table, a generic Win32 FFI
  (`wn.call('user32','MessageBoxW', ...)`), an x64 user-mode inline-hook
  engine, a clap-style argument parser (`WClap.h`) with styled help, a
  manifest-based plugin system, ghost-process detection, an ASCII process
  tree, HWND utilities, full Ctrl+C unwinding, and SCM-backed install /
  uninstall;
- a static library (`WinternalCore.lib`) that user-mode callers can link
  directly if they don't want the CLI.

**Threat model: research on a snapshotted VM.** The driver is test-signed
and runs only with `bcdedit /set testsigning on`. The IOCTL surface is
locked at `\\.\Winternal` to SYSTEM + Administrators via SDDL. None of
this is intended for production endpoints.

## AI usage disclosure

Substantial portions of this codebase — driver IOCTLs, the kernelized
process-inspection paths, the WClap argument parser, the host-marker
plugin protocol, the `wnk.*` Lua surface, and most of the documentation
you're reading — were written collaboratively with an LLM (Anthropic's
Claude). Architecture choices, security trade-offs, and final code
review are human decisions; the LLM was used as an accelerator for
boilerplate, idiomatic plumbing, and consistency passes across the
surface. Files like `Public.h`, `Queue.c`, `WClap.h`, the `wn.*` and
`wnk.*` registries, and this README all reflect that workflow.

If you fork or extend the project, the same standard applies: review
everything that touches kernel state by hand, regardless of who wrote
it. The blast radius of a wrong `kwrite` is the same whether a human or
a model typed it.

## Layout

```
Winternal/                  KMDF kernel driver
  Public.h                  IOCTLs + structs shared with user mode
  Queue.c                   dispatch + kernel hooks + wnk.* bindings + audit
  Device.c                  WdfDeviceInitAssignSDDLString
  Driver.c                  DriverEntry + unload (uninstalls all khooks)
  klua/                     Lua 5.4 vendored for in-kernel execution
    klua_kernel.c           kernel allocator + Zw*-backed fopen/fread/...
    klua_kernel.h           force-included into every Lua source
    lua/src/*.c             stock Lua 5.4 — unmodified

WinternalCore/              static lib
  src/Driver.{h,cpp}        DriverSession — C++ wrapper over the IOCTLs
  src/Process.{h,cpp}       PEB / module / token / handle helpers
  src/Module.{h,cpp}        user-mode module enumeration
  src/KernelModule.{h,cpp}  kernel module list (NtQuerySystemInformation)
  src/Service.{h,cpp}       SCM service enumeration + control
  src/Network.{h,cpp}       TCP/UDP endpoint table (GetExtendedTcpTable)
  src/Handle.{h,cpp}        system-wide handle table + close-remote-handle
  src/ObjectDir.{h,cpp}     NT object directory traversal
  src/Hook.{h,cpp}          user-mode IAT/inline scanner
  src/Util.{h,cpp}          string + token helpers, HandleGuard, etc.
  src/NtApi.h               curated ntdll forward decls

WinternalCLI/               Winternal.exe
  WinternalCLI.cpp          subcommand dispatch + ghost detection + tree
  WinternalInstall.cpp      install / uninstall / status / selftest
  WinternalDriverMgmt.cpp   `drv` group (SCM + force-unload via the driver)
  WinternalPlugins.{h,cpp}  manifest discovery + host-marker protocol
  WinternalLua.cpp          embedded Lua 5.4 + wn.* bindings
  WClap.h                   single-header clap-style arg parser w/ ANSI styling
  Hook64.{h,cpp}            x64 user-mode inline-hook engine
  PluginAPI.h               native-plugin ABI (DLL plugins)
  lua/                      Lua 5.4 vendored (fetched on first build)
  plugins/                  per-plugin folders with plugin.lua manifest
    pg_disable/             PatchGuard `KiFilterFiberContext` scaffold
    example/                kernel-side `wnk.*` demo

tools/
  fetch-lua.ps1             downloads Lua 5.4.7 from lua.org
  new-test-cert.ps1         self-signed code-signing cert for testsigning
```

Build artifacts land in `x64/Release/` at the repo root (flat, one folder)
since `build.ps1` overrides `OutDir`.

## Build

```powershell
# from the repo root
./build.ps1                            # Release | x64
./build.ps1 -Config Debug
./build.ps1 -Skip driver               # skip the kernel driver
```

Requirements: Visual Studio 2026 (toolset v145), Visual Studio 2022 (driver
build only — WDK ships toolset 17.0 task assemblies), Windows 11 SDK
10.0.26100, WDK 10.0.26100. The first build runs `tools/fetch-lua.ps1`
which downloads Lua 5.4.7 from lua.org and unpacks it into the CLI's
include path. The kernel-side Lua sources live separately in
`Winternal/klua/lua/src/` (committed alongside the driver project).

Test-signing: `./tools/new-test-cert.ps1 -InstallTrusted` generates and
installs a `CN=WinternalTestCert` cert. Combine with
`bcdedit /set testsigning on` (then reboot) to make the driver loadable.

## Install + lifecycle

```powershell
winternal install                      # admin: copy .sys, sc create kernel, sc start (default)
winternal install --no-start           # install but don't start the service
winternal selftest                     # round-trip every IOCTL
winternal status                       # service state, testsigning, driver online?
winternal uninstall                    # sc stop + sc delete + remove file
```

`install` looks for `Winternal.sys` next to the exe first, falling back to
the dev-build path; override with `--path <full>`. The file is copied to
`%SystemRoot%\System32\drivers\Winternal.sys`. `uninstall` is idempotent.

## CLI surface

All subcommands print their own clap-style `--help` (styled with bold +
underline section headers, dynamic terminal-width detection). Top-level
`winternal --help` lists every command grouped by section.

```text
User-mode enumeration (no driver needed):
  ps [--hidden] [<pid>]      drivers      svc [<name>]      net
  obj <path>                 handles list [--pid N]
  handles close <pid> <hv>   close a specific handle inside another process
                             (DuplicateHandle + DUPLICATE_CLOSE_SOURCE)

Processes -- inspection, lifecycle, monitoring, protection (all under `proc`):
  proc tree                                       ASCII process tree (DKOM-resistant
                                                  when Winternal.sys is loaded)
  proc dlls    <pid>                              PEB LDR walk (DLLs loaded in target)
  proc threads <pid>                              kernel-side ZwQSI thread walk
  proc mem     <pid> [--commit] [--exec]          KeStackAttach + ZwQueryVirtualMemory
  proc hooks   <pid> [--inline]                   IAT (and optionally inline) hook scan
  proc token   <pid>                              integrity / elevation / UIAccess / privs
  proc mitigations <pid>                          DEP / ASLR / CFG / shadow-stack / signing
  proc ghost   [--kill <pid>] [--kill-all] [-y]   HIDDEN / ZOMBIE / IMG-GONE detection
  proc kill    <pid> [--exit N]                   TerminateProcess + handle-dup-close
                                                  + per-thread fallbacks
  proc kkill   <pid|name> [--glob] [--all] [-t]   driver-side PsTerminateProcess
                                                  [--dry-run] [--exit-code N]
  proc suspend <pid>     proc resume <pid>        NtSuspendProcess / NtResumeProcess
  proc lock    <pid> [--level N] [--force]        set ProcessProtection + Ob handle
                                                  lockdown (was top-level `protect`)
  proc lock    --list                             list locked PIDs
  proc unlock  <pid> [val] [off]                  reverse of `proc lock`
  proc monitor [--include PAT] [--exclude PAT]    live create/exit/terminate stream
               [--cmd] [--nocolor]                via PsSetCreateProcessNotifyRoutineEx
                                                  + undocumented NtTerminateProcess hook
  proc rule add <pat> <allow|deny|log>            create-time block rules
            [--status NTSTATUS]                   (custom NTSTATUS on DENY when the
                                                  inline hook is live; otherwise the
                                                  CreationStatus veto path is used)
  proc rule list | remove <id> | clear
  proc protect add <pat> [--status NTSTATUS]      block process TERMINATION by image
                                                  pattern. Inline hook path returns
                                                  the requested NTSTATUS verbatim;
                                                  Ob-fallback path (HVCI default)
                                                  yields STATUS_ACCESS_DENIED.
  proc protect list | remove <id> | clear

Kernel callbacks / SSDT (non-per-PID inspection):
  callbacks [process|image|thread]                kernel notify routines
  kdrivers    ssdt

Windows (HWND operations -- all under `win`):
  win list [--pid N] [--title PAT] [--class PAT] [--visible]
  win info  <hwnd>                                full window info dump
  win close <hwnd>                                WM_CLOSE (polite, runs target's exit code)
  win destroy <hwnd>                              DestroyWindow direct -- exercises the
                                                  driver block-destroy hook
  win kill  <hwnd>                                WM_CLOSE + driver kkill if it survives
  win hide  <hwnd>    win show <hwnd>             ShowWindow(SW_HIDE|SW_SHOWNA)
  win front <hwnd>                                foreground with attach-input bypass
  win topmost <hwnd> [off]                        toggle WS_EX_TOPMOST
  win zbid <hwnd> [band 0..18]                    read/set the internal Z-band
  win privacy <hwnd> [none|monitor|hide]          display-affinity (anti-screen-cap)
  win move <hwnd> <x> <y> [w h]                   reposition (and optionally resize)
  win protect [--stop]                            run / stop the user-mode guardian that
                                                  enforces close/create rules via
                                                  WH_CALLWNDPROC + WH_CBT
  win rule add --action close|create|destroy      add a window rule (driver-resident);
              ( --title PAT | --class PAT |       close/create are user-mode (need the
                --pid N    | --image PAT )        guardian); destroy installs a kernel
                                                  inline hook on NtUserDestroyWindow
                                                  and is caller-based (--pid / --image
                                                  only)
  win rule list | remove <id> | clear

Kernel primitives (admin + loaded Winternal.sys):
  kver | kpids
  kr <addr> <len>          kw <addr> <hex>             ksym <name>
  kalloc <size> [paged|nonpaged]                       kfree <addr>
  kcall <addr> [a1..a4]

Scripting:
  lua [script.lua | -e expr]    run user-mode Lua with the wn table
                                (REPL when no arg)

Service management (admin):
  install [--path SYS] [--no-start]    uninstall    status    selftest
  selfprotect [on|off|status]          block external tampering
  recover                              re-grant DACL after a botched selfprotect

Driver management (admin):
  drv list | start | stop | enable | disable | delete <name>
  drv load <name> <sys-path>
  drv unload <name>                     force unload via Winternal.sys

NTFS monitoring + analyzing:
  ntfs vols                             NTFS volumes + cluster/MFT metadata
  ntfs usn <vol> [--tail] [--count N]   USN journal snapshot or live tail
  ntfs monitor <vol> [--reasons LIST]   colorized real-time activity stream
  ntfs mft <vol> [--limit N] [--name S] MFT walk via FSCTL_ENUM_USN_DATA
  ntfs streams <path>                   alternate data streams (ADS)
  ntfs compare <path>                   FindFirstFile vs MFT diff (hide detect)
  ntfs raw <device> <off> <len>         driver-backed raw read (bypasses minifilters)
  ntfs filter add <pat> <action>        block/redirect file opens (kernel minifilter)
  ntfs filter list | remove <id> | clear

Plugins:
  plugin list                        plugin info <name>
  plugin enable|disable <name>       plugin run <name>
```

### `proc kill` fallback chain

`proc kill <pid>` tries each user-mode termination technique in order and reports
which one stuck:

1. `TerminateProcess(handle, code)` — needs `PROCESS_TERMINATE`.
2. **Handle-dup-close** — enumerate every handle the target owns via
   `NtQuerySystemInformation(SystemExtendedHandleInformation)`, then yank each
   one with `DuplicateHandle(target, h, self, &out, 0, 0, DUPLICATE_CLOSE_SOURCE)`.
   Needs `PROCESS_DUP_HANDLE` on the target. This is the indirect-kill path
   Win11 Task Manager's End Task falls back to when direct termination fails.
3. **Per-thread terminate** — enumerate threads via `SystemProcessInformation`,
   `OpenThread(THREAD_TERMINATE)` + `TerminateThread` each. Once every thread
   is gone the process tears down.

Each step waits up to 250–500 ms with `WaitForSingleObject` before declaring
success, so a `DuplicateHandle` that closed a non-load-bearing handle doesn't
get reported as a kill. No `WM_CLOSE` / window path — that's `win close <hwnd>`.

### `proc protect` and HVCI

`proc protect` has two enforcement paths and the CLI tells you which is live
after `add`:

- **Inline hook** (CR0.WP-toggle write to `NtTerminateProcess` prologue). Can
  return any per-rule NTSTATUS to the terminator. HVCI / Memory Integrity
  typically rejects the CR0 toggle and the hook fails to install.
- **Ob fallback** (`ObRegisterCallbacks` on `PsProcessType` / `PsThreadType`).
  Strips `PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE` and
  the sentinel bits (`MAXIMUM_ALLOWED`, `GENERIC_*`) from new handles. Always
  yields `STATUS_ACCESS_DENIED` regardless of `--status`. HVCI-safe.

Neither path blocks **self-termination**. Win11 Task Manager's End Task starts
with `SendMessageTimeoutW(hwnd, WM_SYSCOMMAND, SC_CLOSE, ...)`; a target that
honors `WM_CLOSE` calls `ExitProcess` on itself, which is
`NtTerminateProcess(NtCurrentProcess(), 0)` with the implicit `-1` self-handle.
That handle never goes through `OpenProcess`, so no Ob pre-op fires. The only
thing that could block self-termination is the inline hook, which HVCI is
blocking. If you need that on HVCI, disable Memory Integrity (Windows Security
→ Device Security → Core Isolation), reboot, and re-add the rule.

### `win rule` and the destroy-hook trampoline

`win rule` has three actions, two enforcement layers, and one nontrivial
trampoline-relocator the destroy path needs to run on stock Win11 26100:

- `--action close` and `--action create` -- enforced by the **user-mode
  shield DLL** (`WinternalWinShield.dll`) that the `win protect`
  guardian injects into every GUI process via `SetWindowsHookEx`. close
  drops `WM_CLOSE` / `WM_SYSCOMMAND(SC_CLOSE)` / `WM_QUERYENDSESSION`
  via subclassing; create aborts `CreateWindowEx` via `WH_CBT`. Rules
  live in the driver (so they survive across guardian restarts) and are
  mirrored into a shared mapping the guardian polls by generation tick.
- `--action destroy` -- enforced by a **driver-side inline hook** on
  win32k's `NtUserDestroyWindow` syscall stub. Caller-based, so only
  `--pid` and `--image` rule kinds apply (resolving HWND -> properties
  would require walking win32k internals). The CLI pre-resolves the RVA
  via DbgHelp + the Microsoft symbol server when available, so the
  driver hits non-exported workers too; if that fails, the driver falls
  back to its own export-table walk.

Three things make the destroy hook fragile in ways the doc-equivalent
`proc protect` hook isn't:

1. **win32kfull.sys is a session driver.** Its image base reported by
   `SystemModuleInformation` is a session-space VA that only has a
   backing PTE in processes that have actually issued a USER syscall.
   `winternal.exe` is a console app and typically hasn't, so a naive
   read of the prologue from the IOCTL caller's context faults on a
   kernel address with no PTE -- which is `PAGE_FAULT_IN_NON_PAGED_AREA`,
   a bugcheck path SEH cannot catch. The driver fixes this by iterating
   `SystemProcessInformation`, picking processes where
   `PsGetProcessWin32Process != NULL`, and `KeStackAttach`-ing while
   probing the target VA with `MmIsAddressValid` until one matches.
2. **The prologue contains a RIP-relative `mov r10, [rip+disp32]`**
   (almost certainly the `__security_cookie` / CFG dispatch table load
   the compiler emits). The minimal length disassembler has to decode
   the full ModRM/SIB encoding -- a "reg-direct only" simplification
   undercounts this 7-byte instruction as 3, the prologue copy stops
   mid-instruction, and the trampoline executes garbage that resolves
   to freed pool. The fix is a proper ModRM decode for `8B/89` covering
   all five addressing modes (reg-direct, RIP-rel, SIB, disp8, disp32).
3. **Trampoline locality.** Modern Win11 KASLR puts non-paged pool ~27TB
   away from win32kfull's image, far past `disp32`'s ±2GB reach, so even
   a correctly-sized trampoline can't preserve RIP-relative semantics by
   plain disp rewriting. The relocator first tries direct delta, then
   falls back to **snapshot-via-data-slot**: read the 8 bytes the
   original instruction would have referenced (safe -- we're attached
   to a win32k-mapped process), stash them in an 8-byte slot at the
   tail of the trampoline pool allocation, and rewrite the instruction's
   `disp32` to point at the slot. Works for stable references (IAT
   entries, security cookies, CFG tables) -- not for live mutable
   kernel state.

HVCI: same concern as `proc protect`. The CR0.WP toggle is rejected on
HVCI-on machines, the CR0 path falls back to the MDL-alias write path,
and if the EPT is also write-protecting the underlying PFN that path
fails too. The rule is still stored on hook-install failure; the CLI's
`win rule add` output flags `[hook-INACTIVE]` and surfaces the install
NTSTATUS so you know which layer rejected the patch.

Global behavior: `--debug` is accepted on most subcommands and prints
intermediate IOCTL traffic; Ctrl+C cancels in-flight `DeviceIoControl`
calls via `CancelSynchronousIo`, runs RAII destructors so scoped patches
(UIAccess, signature level, kcode_patch originals) revert cleanly.

## Lua: user-mode `wn.*`, kernel-mode `wnk.*`

The CLI embeds Lua 5.4 with a `wn` table that bundles every user-mode
enumeration helper, every driver IOCTL, a generic Win32 FFI, and an x64
inline-hook engine. The driver embeds its own Lua 5.4 (different state)
with a `wnk` table exposing kernel primitives directly — no IOCTL hop.

```lua
-- inspect processes (user mode)
for _, p in ipairs(wn.ps()) do
    if p.name == 'lsass.exe' then print('lsass', p.pid) end
end

-- call any Win32 API
local hwnd = wn.call('user32', 'GetForegroundWindow')
wn.call('user32', 'MessageBoxW', hwnd, {wstr='hi'}, {wstr='Winternal'}, 0)

-- read kernel memory
local addr = wn.ksym('PsLookupProcessByProcessId')
local prologue = wn.kread(addr, 64)

-- hook GetCurrentProcessId to return 0x539 = 1337
local d = wn.alloc_exec(64); wn.write(d, '\xb8\x39\x05\x00\x00\xc3')
local tramp = wn.hook(wn.proc('kernel32', 'GetCurrentProcessId'), d)
print(wn.call('kernel32', 'GetCurrentProcessId'))     -- 1337
wn.unhook_all()

-- ship a script to the driver
local out, status = wn.kernel_run([[
    local n = #wnk.pids()
    print(string.format('kernel saw %d processes', n))
]])
io.write(out)
```

**Bindings on `wn` (CLI):** ps, dlls, drivers, svc, net, handles, obj,
hooks, kill, suspend, resume, kver, kpids, kread, kwrite, ksym, kalloc,
kfree, kcall, unprotect, kkill, callbacks, kdrivers, ssdt, proc, call,
alloc, free, read, write, wreadstr, cstr, wstr, lasterror, hook, unhook,
unhook_all, alloc_exec, flush_icache, khook, kunhook, kunhook_all,
kernel_run, lockdown_engage, lockdown_status, audit_tail, drv_unload,
kdrv_register, kdrv_deregister, kdrv_load, kdrv_unload, kdrv_set_start.

**Bindings on `wnk` (kernel-side Lua):** the full driver surface is
exposed so plugins can run entire ARK workflows inside the driver without
an IOCTL round-trip per primitive. Grouped:

- **basics** — `print`, `ksym`, `modksym`, `module`, `scan`, `kread`,
  `kreadstr`, `kwrite`, `kalloc`, `kfree`, `pids`
- **ntfs / fs** — `ntfs_raw_read` (raw bytes from any kernel device),
  `ntfs_usn_query` / `ntfs_usn_read` (USN journal), `ntfs_mft_enum`
  (MFT walk via FSCTL_ENUM_USN_DATA), `ntfs_streams`
  (FileStreamInformation). All open their target with
  `PreviousMode = Kernel`, so the underlying FSCTL hits NTFS unfiltered
  by per-process / per-access-mode minifilters.
- **call + EPROCESS field tools** — `kcall`, `unprotect`, `kill`,
  `protect_lock`, `protect_unlock`, `protect_list`, `set_siglevel`,
  `token_uiaccess`, `kcode_patch`, `get_true_stub`, `get_w32proc`
- **process inspection** — `threads`, `mitigations`, `token_info`,
  `mem_query` (each runs the same `KeStackAttach + Zw*` path the IOCTL
  uses, so user-mode hooks can't filter the result)
- **rootkit detection** — `callbacks` (process/image/thread),
  `kdrivers`, `ssdt`
- **inline hooks** — `khook`, `kunhook`, `kunhook_all` (IPI-broadcast
  prologue patch, same engine as the IOCTL)
- **lockdown / audit** — `lockdown_engage`, `lockdown_status`,
  `audit_tail`
- **driver lifecycle** — `force_unload`, `kdrv_register`, `kdrv_load`,
  `kdrv_unload`, `kdrv_deregister`, `kdrv_set_start`

Write-side bindings honor lockdown: once `wnk.lockdown_engage()` (or its
IOCTL twin) fires, subsequent write/patch calls error with `"lockdown
engaged"`. Read-only enumerations stay open.

The kernel Lua has a real `fopen`/`fread`/`time`/`clock`/`malloc`
(`ZwCreateFile`/`ZwReadFile`/`KeQuerySystemTime`/`ExAllocatePool2`),
plus `string.pack` / `string.unpack` (Lua 5.4 stdlib), so plugins can
marshal arbitrary native structs in pure Lua. No `os` / `package` /
`io.popen` / `debug.gethook` and no math.h-based functions.

### Calling undocumented / arbitrary Windows APIs

Plugins can call any export of any loaded kernel module — not just
ntoskrnl + hal — and pass arbitrary structs built with `string.pack`.
The same primitives the compiled C code uses:

| Need                            | Use                                                |
| ------------------------------- | -------------------------------------------------- |
| Resolve a known nt/hal export   | `wnk.ksym("RtlGetVersion")`                        |
| Resolve any other kmod export   | `wnk.modksym("tcpip.sys", "TcpEnumerateAllConnections")` |
| Find an *unexported* routine    | `wnk.scan(info.base, info.size, "48 89 5C 24 ? 57")` |
| Get module base + size          | `info = wnk.module("ntoskrnl.exe")`                |
| Build a native struct           | `string.pack("<I4 I4 z", size, flags, name)`       |
| Pin it in kernel memory         | `buf = wnk.kalloc(size, false); wnk.kwrite(buf, blob)` |
| Call with up to 12 args         | `rv, faulted = wnk.kcall(addr, buf, ...)`          |
| Read result back                | `wnk.kread(buf, size)` + `string.unpack(...)`      |
| Read NUL-terminated kernel str  | `wnk.kreadstr(p, 256)`                             |
| Free your buffer                | `wnk.kfree(buf)`                                   |

`wnk.kcall` is variadic up to 12 args (covers ~all NT APIs); SEH-wrapped,
so a target that AVs sets `faulted = true` instead of bug-checking the
dispatch thread. Integers, booleans, strings (passed as raw pointers),
and `nil` (= 0) coerce automatically. For pointer-to-struct args you
build the struct yourself (`string.pack` + `wnk.kalloc` + `wnk.kwrite`)
and pass the resulting address.

```lua
-- Get the kernel's view of the OS version via undocumented-class
-- KUSER_SHARED_DATA fields would be one path; here's the documented but
-- struct-heavy RtlGetVersion path, illustrating the marshalling pattern.
local OSVERSIONINFOEXW_SIZE = 284
local buf = wnk.kalloc(OSVERSIONINFOEXW_SIZE, false)
-- First field of OSVERSIONINFOEXW is dwOSVersionInfoSize.
wnk.kwrite(buf, string.pack("<I4", OSVERSIONINFOEXW_SIZE))
local rv, faulted = wnk.kcall(wnk.ksym("RtlGetVersion"), buf)
if not faulted and rv == 0 then
    local blob = wnk.kread(buf, OSVERSIONINFOEXW_SIZE)
    local _, maj, min, build = string.unpack("<I4 I4 I4 I4", blob)
    print(string.format("Windows %d.%d build %d", maj, min, build))
end
wnk.kfree(buf)

-- Resolve and call a non-ntoskrnl export. Example: tcpip.sys's
-- documented IpFwQueryDefaultPolicy, or any other driver export.
local fn = wnk.modksym("tcpip.sys", "IpFwQueryDefaultPolicy")
if fn then print(string.format("tcpip!IpFwQueryDefaultPolicy @ 0x%X", fn)) end
```

```lua
-- A "do-everything" example: PG-disable, unprotect lsass, install an
-- inline hook on PsLookupProcessByProcessId so a chosen PID becomes
-- invisible to the kernel, snapshot the kernel callbacks for proof,
-- freeze further writes. All in one kernel-side script, no IOCTL hops.
local kfc = wnk.ksym("KiFilterFiberContext")
wnk.kcode_patch(kfc, "\x33\xC0\xC3\x90")           -- xor eax,eax; ret; nop

for _, p in ipairs(wnk.pids()) do
    if p.name:match("lsass") then wnk.unprotect(p.pid) end
end

local detour = wnk.kalloc(64, true)                -- non-paged, executable
wnk.kwrite(detour, "\x48\x31\xC0\xC3")             -- xor rax,rax; ret  (stub)
local tramp = wnk.khook(wnk.ksym("PsLookupProcessByProcessId"), detour, 16)
print("trampoline @", string.format("0x%X", tramp))

for _, cb in ipairs(wnk.callbacks("process")) do
    print(string.format("[cb] %-20s 0x%X", cb.moduleName, cb.routine))
end

wnk.lockdown_engage()                              -- one-way kill switch
```

## Plugins

Layout: each plugin is a folder with a `plugin.lua` manifest and an entry
file the manifest names.

```
plugins/
  example/
    plugin.lua          -- manifest table
    main.lua            -- runs in the driver via IOCTL_LUA_EXEC
  netmon/
    plugin.lua
    main.dll            -- runs in the CLI, exports WinternalPluginInit
```

`plugin.lua` returns a table:

```lua
return {
    name        = "example",
    version     = "0.1.0",
    description = "Banner + kernel PID enum demo",
    type        = "lua-kernel",        -- or "lua-user", "dll"
    entry       = "main.lua",
    depends     = {},
    autorun     = true,                -- optional; see below
    commands    = { { name = "demo-banner", description = "..." } },
}
```

Per-plugin enable/disable state is persisted in
`%APPDATA%\Winternal\plugins.lua`. `winternal plugin run <name>
[args...]` always invokes a plugin explicitly; everything after the
plugin name is exposed inside the script as the standard Lua `arg`
table, so plugins implement their own subcommands / options:

```powershell
winternal plugin run pg_disable                # self-toggle
winternal plugin run pg_disable status         # show current state
winternal plugin run pg_disable pg-disable     # explicit disable
winternal plugin run pg_disable pg-revert      # explicit revert
```

```lua
-- inside main.lua
local cmd = arg and arg[1]
if cmd == "status" then ... end
```

Combine with `string.pack` / a small option parser in Lua for richer
grammars. The manifest's `commands` array is purely descriptive — the
plugin itself owns dispatch. **Autorun behavior** for `winternal lua`
startup is opt-in per plugin via the `autorun` manifest field:

- `lua-user` and `dll` — default `autorun = true`. These plugins
  typically register helpers into `wn.*`, so loading them at every Lua
  startup is the expected shape.
- `lua-kernel` — default `autorun = false`. These plugins act on the
  system (kernel R/W, patches, hooks) and would do destructive things
  on every `winternal lua` invocation. Set `autorun = true` in the
  manifest if you really want fire-on-start.

`plugin info <name>` shows the resolved `autorun:` value alongside
state. Native DLL plugins must export `WinternalPluginInit` (ABI in
`WinternalCLI/PluginAPI.h`); they get a `WinternalHost*` with a Lua state,
the driver session, and `register_function` / `log` callbacks.

Search paths (created on first use):
- `<exe-dir>/plugins/`
- `%USERPROFILE%/.winternal/plugins/`

### Host-marker protocol

Kernel-Lua plugins have `fopen` / `fread` (Zw*-backed) for *reading* state
files but no write side. The runner gives them one via a structured
stdout marker:

```lua
-- inside a kernel-Lua plugin
local path = "C:\\ProgramData\\Winternal\\state.lua"
local body = 'return { foo = 42 }\n'
print(string.format("[winternal-host] write_file %s %s",
    hex(path), hex(body)))
```

The runner scans plugin output for `[winternal-host] <verb> ...` lines
and acts on them. Both args are UTF-8 hex so paths and binary payloads
round-trip without escape issues. Verbs:

| Verb         | Arguments              | Effect                                  |
| ------------ | ---------------------- | --------------------------------------- |
| `write_file` | `<path-hex> <data-hex>` | mkdir + binary-write the file           |
| `delete_file`| `<path-hex>`           | remove the file (no-op if missing)      |

`plugins/pg_disable/main.lua` uses this protocol to auto-persist its
state file across the disable / revert cycle.

## Driver IOCTL surface (Public.h)

| IOCTL                                | What it does                                  |
| ------------------------------------ | --------------------------------------------- |
| `GET_VERSION` / `ENUM_PIDS`          | sanity check + DKOM-resistant PID enum        |
| `KMEM_READ` / `KMEM_WRITE`           | arbitrary kernel R/W (capped 1 MiB / call)    |
| `KSYM`                               | `MmGetSystemRoutineAddress`                   |
| `KALLOC` / `KFREE`                   | `ExAllocatePool2` / `ExFreePoolWithTag`       |
| `KCALL`                              | call kernel routine with 4 args, SEH-wrapped  |
| `KCODE_PATCH`                        | CR0.WP-toggled write into kernel CODE pages   |
| `GET_TRUE_STUB`                      | address of "always returns 1" stub for IAT redirects |
| `GET_W32PROC`                        | EPROCESS->Win32Process (tagPROCESSINFO*)      |
| `UNPROTECT_PROCESS`                  | clear `EPROCESS->Protection` (PPL/PP)         |
| `KILL_PROCESS`                       | `PsTerminateProcess` direct (PPL/PP-safe)     |
| `PROTECT_LOCK / UNLOCK / LIST`       | force-protect via Ob pre-op callbacks         |
| `TOKEN_UIACCESS`                     | toggle `TOKEN_HAS_UI_ACCESS` (skips SeTcb)    |
| `SET_SIGLEVEL`                       | write EPROCESS SignatureLevel / SectionSig    |
| `ENUM_THREADS`                       | kernel-side thread list (bypasses UM hooks)   |
| `K_MITIGATIONS`                      | DEP/ASLR/CFG/shadow-stack/sig policies        |
| `K_TOKEN_INFO`                       | integrity, elevation, UIAccess, privileges    |
| `K_MEM_QUERY`                        | KeStackAttach + ZwQueryVirtualMemory walk     |
| `ENUM_CALLBACKS / DRIVERS / SSDT`    | rootkit-detection enumerators                 |
| `KHOOK_INSTALL / UNINSTALL[_ALL]`    | x64 inline hook engine (IPI-broadcast patch)  |
| `LUA_EXEC`                           | run Lua script in kernel with `wnk.*`         |
| `LOCKDOWN_ENGAGE / STATUS`           | one-way kill switch                           |
| `AUDIT_TAIL`                         | read last N audit rows                        |
| `FORCE_UNLOAD_DRIVER`                | resolve `\Driver\<name>` + call DriverUnload  |
| `KDRV_REGISTER / LOAD / UNLOAD / DEREGISTER / SET_START` | SCM-bypassing driver lifecycle (ZwLoadDriver + reg writes) |
| `NTFS_RAW_READ`                      | ZwReadFile on a `\Device\*` from kernel mode |
| `NTFS_VOL_DATA / USN_QUERY / USN_READ / MFT_ENUM / STREAMS` | FSCTL passthrough via `ZwFsControlFile` + `ZwQueryInformationFile` (PreviousMode=Kernel) |
| `NTFS_FILTER_ADD / REMOVE / LIST / CLEAR` | rule-driven minifilter (FltRegisterFilter + pre-create); in-house path-aware wildcard matcher (`*` spans `\`); actions deny / notfound / readonly / log — HVCI-compatible |
| `PROC_MONITOR_START / STOP / READ`   | real-time process create/exit stream via PsSetCreateProcessNotifyRoutineEx; in-kernel ring buffer + KEVENT, blocking IOCTL with 2s timeout for clean Ctrl+C |
| `PROC_RULE_ADD / REMOVE / LIST / CLEAR` | image-path wildcard rules consulted from the same notify routine; `deny` sets `CreationStatus = STATUS_ACCESS_DENIED` (process create fails at the syscall), `log` audits but allows |
| `WIN_RULE_ADD / REMOVE / LIST / CLEAR` | driver-resident window rules (title/class/pid/image patterns × close/create/destroy actions). Storage is the source of truth for both the user-mode shield DLL (close/create) and the in-kernel `NtUserDestroyWindow` hook (destroy). |
| `HOOK_INSTALL_BY_RVA`                | install a named inline hook by `(module-basename, RVA)` -- CLI pre-resolves via DbgHelp + Microsoft symbol server and hands the driver an absolute target. Currently dispatches to the destroy-window hook installer; new HookIds extend the table in lockstep with `Public.h`. |
| (no IOCTL, internal)                 | **undocumented NtTerminateProcess prologue hook** — patches the syscall entry to surface caller→target attribution as `TERMINATE_REQ` events in the proc-monitor ring before the kernel processes the terminate |
| (no IOCTL, internal)                 | **NtUserDestroyWindow prologue hook** -- caller-based block-destroy enforcement; runs the session-attach + ModRM-aware LDE + data-slot RIP-rel relocator described in the `win rule` section above |
| `SELFPROTECT_SET / STATUS`           | owner-PID gate on weaken-protection IOCTLs (force-unload, protect-unlock, selfprotect-off) |

Every state-mutating IOCTL is SEH-wrapped at the dispatcher level, audited
into a 1024-row ring buffer, and refused once lockdown is engaged.
Kernel-pointer args are validated against `>= 0xFFFF800000000000` (x64
canonical kernel range) before any read/write.

### `khook` is SMP-safe

`KHOOK_INSTALL` and `KHOOK_UNINSTALL[_ALL]` patch via `KeIpiGenericCall`:
every other CPU is paused at IPI_LEVEL while one CPU clears CR0.WP, writes
the prologue, restores CR0.WP, and ack's. Targets running on other cores
never see a half-written prologue.

## Self-protection

```powershell
winternal selfprotect on                        # engage
winternal selfprotect status
winternal selfprotect off                       # disengage
```

Engaging makes the driver + service actively resist tampering from
other admin-elevated processes:

| Vector                              | Mitigation                                              |
| ----------------------------------- | ------------------------------------------------------- |
| `sc stop Winternal` from anyone — admin, SYSTEM, scheduler task | Kernel-mode hook on `NtUnloadDriver` refuses calls whose `DriverServiceName` ends in `\Winternal` while self-protect is engaged. SCM DACL is a secondary layer; the syscall hook is the actual stop-prevention since admin → SYSTEM is trivial. |
| `sc delete Winternal`               | Service DACL (SYSTEM-only) — bypassable by SYSTEM-elevated processes, but the syscall hook above means even after `sc delete` the driver stays loaded until reboot. |
| `winternal drv unload Winternal` from another binary | Dispatcher refuses `FORCE_UNLOAD_DRIVER` / `KDRV_UNLOAD` targeting "Winternal" unless the caller's image SHA-256 matches the owner's hash. |
| Another admin calling `protect-unlock` on the owner | Dispatcher refuses `PROTECT_UNLOCK` of the owner PID unless the caller's hash matches. |
| Another admin calling `selfprotect off` | Dispatcher refuses `SELFPROTECT_SET(0)` unless the caller's hash matches. |

What `selfprotect` deliberately does **not** do: add the engaging CLI's
PID to the Ob protect-list. The CLI is one-shot — it exits seconds
after `selfprotect on` returns — so a PID-based filter would only
briefly cover the CLI itself and then leak a stale (potentially-reused)
PID into the protect list. If you want OpenProcess filtering on an
interactive session (e.g. `winternal lua` REPL), run
`winternal proc lock <pid> --force` from inside it; the Ob surface is
intentionally a separate, manually-invoked tool from `selfprotect`.

Identity check uses a **SHA-256 of the caller's main image** computed
in kernel mode via BCrypt. On `selfprotect on` the driver locates the
calling process's image with `SeLocateProcessImageName`, reads the
on-disk bytes (capped at 16 MiB) via `ZwReadFile` with
`PreviousMode=Kernel`, hashes them, and stores the 32-byte digest. On
every later weaken-protection IOCTL the driver re-hashes the current
caller's image and compares — letting subsequent invocations of the
*same binary* (across reboots of the CLI process, not the OS) through
while refusing anything else, including a process that's been renamed
to `Winternal.exe`. Tying to the file's bytes rather than to a PID
also avoids locking-in protection forever when the engaging CLI exits.

If an attacker swaps the `Winternal.exe` on disk *after* engage, their
new file hashes differently and the gate refuses them — but they've
also already broken your tool more fundamentally, so the practical
attack surface is small.

**Not protected against:** kernel-mode tampering (another loaded driver
patching our handlers or restoring our `NtUnloadDriver` prologue), DLL
injection into the CLI before `selfprotect on` runs, an attacker
controlling the binary *before* engage, HVCI swallowing the
`NtUnloadDriver` patch silently (if the readback fails the install
errors; the SCM DACL stays as fallback), or a Windows reboot.
Self-protection is a defense against malware running in an admin
user-mode process — not a substitute for HVCI or signed-driver
enforcement.

## Lockdown + audit

```lua
-- after applying kernel patches, freeze further writes
wn.lockdown_engage()      -- one-way; only clears on driver unload

-- inspect what's been done
for _, row in ipairs(wn.audit_tail(32)) do
    print(string.format(
        '[%d] ioctl=0x%x pid=%d target=0x%x len=%d status=0x%x',
        row.timestampNs, row.ioctl, row.pid, row.target, row.length, row.status))
end
```

The lockdown bit refuses every write/patch IOCTL (`kwrite`, `kalloc`,
`kfree`, `kcall`, `unprotect`, `kill_process`, all `khook*`, `lua_exec`)
with `STATUS_ACCESS_DENIED`. Read-only IOCTLs (`kver`, `kpids`, `kread`,
`ksym`, the enum_* family, audit, status) stay open. Use this after a
risky kernel session so a buggy follow-up script can't worsen things.

## PatchGuard — what this ships and what it doesn't

`plugins/pg_disable/main.lua` is a **research scaffold**, not a full PG
bypass. The script self-toggles: a single `winternal plugin run pg_disable`
patches if the prologue is original, reverts if it's already the patch.
What it does:

- Resolves `KiFilterFiberContext` via `MmGetSystemRoutineAddress`.
- Reads the original 4-byte prologue and persists it to
  `C:\ProgramData\Winternal\pg_state.lua` via the host-marker protocol
  (no manual copy-paste).
- Patches the prologue to `33 C0 C3 90` (`xor eax,eax; ret; nop`).
- Reads back to verify.
- On the revert path, `loadfile()`s the state file, restores the
  original bytes, and emits a `[winternal-host] delete_file` so the next
  run takes the disable path.

What it does **not** do: disable already-running PG verification. By the
time `Winternal.sys` loads, the INIT-segment bootstrap (`sub_140BE00B0`
in build 26100) has been freed and the active PG context lives in
encrypted pool blocks with per-boot seed XOR. Reaching it requires live
WinDbg + per-build IDA work — the script intentionally stops short of
guessing offsets it can't verify, because untested kernel patches
bug-check the VM on first run.

To go further you derive the runtime PG state offsets yourself: search
pool tags `'PgPg'` / `'Cont'`, find the verification routine pointer in
the decrypted context, replace it with a stub. The scaffold has every
primitive you need (`wnk.kread`, `wnk.kwrite`, `wnk.ksym`, `wnk.kcall`).

## Safety

- `\\.\Winternal` open is SYSTEM + Administrators only (SDDL
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)` resolved at AddDevice).
- Every IOCTL handler is SEH-wrapped at the dispatcher; a bug fails the
  request rather than bug-checking the queue thread.
- Caller-supplied kernel addresses are checked against the x64 canonical
  kernel range before any read/write.
- `khook` patching is IPI-broadcast: SMP-coherent across cores.
- Driver unload uninstalls every `khook` before freeing its trampolines.
- `LUA_EXEC` serializes via a fast mutex; one script at a time.
- Lockdown bit is one-way and only clears on driver unload.
- Every privileged IOCTL is audited (caller PID, target, status,
  timestamp) into a 1024-row in-kernel ring.

## Runbook on a fresh VM

```powershell
# 1. one-time cert setup (elevated)
.\tools\new-test-cert.ps1 -InstallTrusted
bcdedit /set testsigning on            # then reboot

# 2. build everything to x64\Release
.\build.ps1

# 3. install + verify
cd x64\Release
.\Winternal.exe install             # elevated
.\Winternal.exe selftest

# 4. ship a kernel script
.\Winternal.exe lua -e "print(wn.kernel_run('print(#wnk.pids())'))"

# 5. when done, freeze + uninstall
.\Winternal.exe lua -e "wn.lockdown_engage()"
.\Winternal.exe uninstall           # elevated
```

## License

GPL 3.0. See `LICENSE` for the full text. Vendored third-party sources
keep their original licenses:

- `WinternalCLI/lua/`, `Winternal/klua/lua/` — Lua 5.4 (MIT).
- everything else under `Winternal/`, `WinternalCore/`, `WinternalCLI/`,
  `tools/`, `plugins/` is GPL 3.0.
