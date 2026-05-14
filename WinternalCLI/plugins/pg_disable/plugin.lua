return {
    name        = "pg_disable",
    version     = "0.1.0",
    description = "Disable PatchGuard via SKT64-style atomic patches (build 26100). Self-toggles: run once to patch, again to revert; state file is persisted automatically via the host-marker protocol.",
    type        = "lua-kernel",
    entry       = "main.lua",
    depends     = {},
    commands    = {
        { name = "pg-disable", description = "Apply the PG-disable patch (errors if already patched)" },
        { name = "pg-revert",  description = "Restore the original 4-byte prologue and delete the state file" },
        { name = "status",     description = "Print the current prologue bytes and patch state" },
        { name = "(no arg)",   description = "Self-toggle: patch if original, revert if patched" },
    },
}
