return {
    name        = "pg_disable",
    version     = "0.1.0",
    description = "Disable PatchGuard via SKT64-style atomic patches (build 26100). Self-toggles: run once to patch, again to revert; state file is persisted automatically via the host-marker protocol.",
    type        = "lua-kernel",
    entry       = "main.lua",
    depends     = {},
    commands    = {
        { name = "pg-disable", description = "Apply the PG-disable patch (auto when KiFilterFiberContext is unpatched)" },
        { name = "pg-revert",  description = "Restore the original 4-byte prologue from C:\\ProgramData\\Winternal\\pg_state.lua and delete it (auto when patched)" },
    },
}
