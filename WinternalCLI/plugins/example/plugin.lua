return {
    name        = "example",
    version     = "0.1.0",
    description = "Banner + kernel PID enum demo",
    type        = "lua-kernel",
    entry       = "main.lua",
    depends     = {},
    commands    = {
        { name = "demo-banner", description = "Print the kernel-side banner" },
    },
}
