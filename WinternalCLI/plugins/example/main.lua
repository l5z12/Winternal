-- Winternal kernel-mode plugin example.
--
-- This .lua file is read by the CLI and shipped to the driver via
-- IOCTL_LUA_EXEC. It runs INSIDE the kernel with the `wnk` table exposed.
-- print() goes to the per-call capture buffer the CLI prints to stderr.

print("[kernel] example.lua loaded inside Winternal.sys")
local sym = wnk.ksym("PsLookupProcessByProcessId")
if sym then
    print(string.format("[kernel] PsLookupProcessByProcessId = 0x%x", sym))
end

-- A trivial DKOM cross-check from inside the kernel.
local pids = wnk.pids()
print(string.format("[kernel] saw %d processes via kernel-side enum", #pids))
