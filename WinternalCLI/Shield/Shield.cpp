// WinternalWinShield.dll - loaded into every GUI process on the desktop
// by SetWindowsHookEx(WH_CALLWNDPROC, ...). Reads a shared file-mapping
// owned by the CLI guardian to learn which windows to protect, and
// installs a SetWindowSubclass on each that drops close-related messages
// (WM_CLOSE / WM_SYSCOMMAND(SC_CLOSE) / WM_QUERYENDSESSION).
//
// Why a separate DLL instead of injecting via CreateRemoteThread + a
// shellcode trampoline: SetWindowsHookEx is the documented path. The
// kernel handles the cross-process LoadLibrary for us, including the
// (numerous) edge cases around protected processes, AppContainer, and
// different desktops on the same session. Cost is one extra binary in
// the deploy folder.

#include <windows.h>
#include <commctrl.h>
#include <stdlib.h>   // _countof
#include <stdint.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")

// Shared state layout — must match the CLI side byte-for-byte.
// Sized for short-lived foreground sessions; bumping these is a binary-
// compat break across CLI and DLL.
// Must match the CLI side byte-for-byte. Session-local namespace so the
// shield (loaded into Medium-IL apps) and the guardian (often elevated)
// can both open it without SeCreateGlobalPrivilege.
#define WINTERNAL_SHIELD_MAP_NAME   L"Local\\WinternalWinShield_v1"
#define WINTERNAL_SHIELD_MAX_HWNDS  256
#define WINTERNAL_SHIELD_MAX_RULES  64
#define WINTERNAL_SHIELD_PATTERN_LEN 128

enum ShieldRuleKind : uint32_t {
    SHIELD_RULE_NONE       = 0,
    SHIELD_RULE_TITLE_GLOB = 1,  // glob against GetWindowText
    SHIELD_RULE_CLASS_GLOB = 2,  // glob against GetClassName
    SHIELD_RULE_PID        = 3,  // exact PID match (pattern parsed as decimal)
    SHIELD_RULE_IMAGE_GLOB = 4,  // glob against the process's exe basename
};

enum ShieldAction : uint32_t {
    SHIELD_ACTION_BLOCK_CLOSE  = 0,  // default — subclass-drop WM_CLOSE
    SHIELD_ACTION_BLOCK_CREATE = 1,  // WH_CBT HCBT_CREATEWND abort
};

struct ShieldRule {
    uint32_t kind;                                  // ShieldRuleKind
    uint32_t action;                                // ShieldAction
    wchar_t  pattern[WINTERNAL_SHIELD_PATTERN_LEN]; // NUL-terminated
};

struct ShieldState {
    volatile LONG generation;                       // CLI bumps on edit
    LONG          hwndCount;
    LONG          ruleCount;
    LONG          _pad;
    HWND          hwnds[WINTERNAL_SHIELD_MAX_HWNDS];
    ShieldRule    rules[WINTERNAL_SHIELD_MAX_RULES];
};

static HANDLE       g_map  = nullptr;
static ShieldState* g_st   = nullptr;
static LONG         g_seen = -1;   // last `generation` we processed in this process

// Tiny case-insensitive glob: `*` matches any run of chars, `?` matches
// exactly one. Same shape as the kernel-side pattern matcher so users
// don't have to remember two flavors. ASCII-fold lowercase for simple
// ASCII match (Windows titles often contain Unicode but the wildcard
// surface is meant for ASCII identifiers like "Notepad", "Chrome", etc.).
static bool GlobMatchCI(const wchar_t* pat, const wchar_t* s) {
    const wchar_t* p = pat;
    const wchar_t* z = s;
    const wchar_t* starPat = nullptr;
    const wchar_t* starS   = nullptr;
    auto lower = [](wchar_t c){ return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c; };
    while (*z) {
        if (*p == L'*') { starPat = ++p; starS = z; continue; }
        if (*p == L'?' || lower(*p) == lower(*z)) { ++p; ++z; continue; }
        if (starPat) { p = starPat; z = ++starS; continue; }
        return false;
    }
    while (*p == L'*') ++p;
    return *p == 0;
}

// The subclass we install on every protected window. UIntPtr id is our
// magic cookie so we can RemoveWindowSubclass on detach without colliding
// with any pre-existing subclass the app installed.
static constexpr UINT_PTR kSubclassId = 0xCAFEBABE;

static LRESULT CALLBACK ShieldSubclass(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                       UINT_PTR id, DWORD_PTR /*data*/) {
    switch (msg) {
    case WM_CLOSE:
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_CLOSE) return 0;
        break;
    case WM_QUERYENDSESSION:
        return FALSE;
    case WM_NCDESTROY:
        // Clean up our subclass before the window goes away so we don't
        // leave a dangling subclass reference in comctl32's chain.
        RemoveWindowSubclass(hwnd, ShieldSubclass, id);
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static bool HwndInList(HWND h) {
    if (!g_st) return false;
    LONG n = g_st->hwndCount;
    for (LONG i = 0; i < n && i < WINTERNAL_SHIELD_MAX_HWNDS; ++i) {
        if (g_st->hwnds[i] == h) return true;
    }
    return false;
}

// Cache the current process's image basename — invariant for the lifetime
// of the DLL inside this process, and otherwise costs a GetModuleFileName
// per evaluated window.
static const wchar_t* CurrentImageBasename() {
    static wchar_t cache[64] = {0};
    if (cache[0]) return cache;
    wchar_t full[MAX_PATH] = {0};
    if (!::GetModuleFileNameW(nullptr, full, MAX_PATH)) { cache[0] = L'?'; cache[1] = 0; return cache; }
    const wchar_t* base = full;
    for (const wchar_t* p = full; *p; ++p) if (*p == L'\\' || *p == L'/') base = p + 1;
    size_t i = 0;
    while (i + 1 < _countof(cache) && base[i]) { cache[i] = base[i]; ++i; }
    cache[i] = 0;
    return cache;
}

// Single-rule check. Used by both the existing HwndMatchesRule path
// (close-blocking) and the new HCBT_CREATEWND path (create-blocking).
// For create-blocking, the title is from CREATESTRUCT->lpszName (may be
// null) and class from CREATESTRUCT->lpszClass (may be ATOM-encoded).
static bool RuleMatchesContext(const ShieldRule& r, const wchar_t* title,
                               const wchar_t* cls, DWORD pid,
                               const wchar_t* img) {
    switch (r.kind) {
    case SHIELD_RULE_TITLE_GLOB:
        return title && *title && GlobMatchCI(r.pattern, title);
    case SHIELD_RULE_CLASS_GLOB:
        return cls && *cls && GlobMatchCI(r.pattern, cls);
    case SHIELD_RULE_PID: {
        DWORD want = 0;
        for (const wchar_t* p = r.pattern; *p >= L'0' && *p <= L'9'; ++p)
            want = want * 10 + (DWORD)(*p - L'0');
        return want != 0 && pid == want;
    }
    case SHIELD_RULE_IMAGE_GLOB:
        return img && *img && GlobMatchCI(r.pattern, img);
    }
    return false;
}

static bool HwndMatchesRule(HWND h) {
    if (!g_st) return false;
    LONG n = g_st->ruleCount;
    if (n <= 0) return false;
    wchar_t title[256]{}, cls[256]{};
    DWORD pid = 0;
    ::GetWindowTextW(h, title, _countof(title));
    ::GetClassNameW(h, cls, _countof(cls));
    ::GetWindowThreadProcessId(h, &pid);
    const wchar_t* img = CurrentImageBasename();
    for (LONG i = 0; i < n && i < WINTERNAL_SHIELD_MAX_RULES; ++i) {
        const ShieldRule& r = g_st->rules[i];
        if (r.action != SHIELD_ACTION_BLOCK_CLOSE) continue;
        if (RuleMatchesContext(r, title, cls, pid, img)) return true;
    }
    return false;
}

// Called from the WH_CBT hook on HCBT_CREATEWND. CREATESTRUCTW may have
// a class encoded as an atom (low word) or a real pointer — disambiguate
// before glob-matching. Returns true to abort the create.
static bool CreateMatchesRule(const CBT_CREATEWNDW* cw) {
    if (!g_st || !cw || !cw->lpcs) return false;
    LONG n = g_st->ruleCount;
    if (n <= 0) return false;
    const CREATESTRUCTW* cs = cw->lpcs;
    const wchar_t* title = cs->lpszName ? cs->lpszName : L"";
    wchar_t classBuf[64] = {0};
    const wchar_t* cls = L"";
    if (cs->lpszClass) {
        // Class names with high word == 0 are atoms; resolve via GetClassInfo
        // would require an HWND. Skip atom-only classes for now — the user
        // can match by image instead.
        ULONG_PTR p = (ULONG_PTR)cs->lpszClass;
        if (p > 0xFFFF) cls = cs->lpszClass;
    }
    DWORD pid = ::GetCurrentProcessId();
    const wchar_t* img = CurrentImageBasename();
    for (LONG i = 0; i < n && i < WINTERNAL_SHIELD_MAX_RULES; ++i) {
        const ShieldRule& r = g_st->rules[i];
        if (r.action != SHIELD_ACTION_BLOCK_CREATE) continue;
        if (RuleMatchesContext(r, title, cls, pid, img)) return true;
    }
    return false;
}

// Walk every top-level window owned by the current process and install
// our subclass on any that match. Called from the hook proc on every
// generation change so adds/removes propagate without per-process LoadLibrary.
static BOOL CALLBACK EnumWindowsApply(HWND h, LPARAM /*lp*/) {
    DWORD pid = 0;
    ::GetWindowThreadProcessId(h, &pid);
    if (pid != ::GetCurrentProcessId()) return TRUE;
    bool want = HwndInList(h) || HwndMatchesRule(h);
    // SetWindowSubclass is idempotent given the same id; the second call
    // just updates data. Safe to call repeatedly in a hot path.
    if (want) ::SetWindowSubclass(h, ShieldSubclass, kSubclassId, 0);
    else      ::RemoveWindowSubclass(h, ShieldSubclass, kSubclassId);
    return TRUE;
}

static void ApplyIfChanged() {
    if (!g_st) return;
    LONG gen = g_st->generation;
    if (gen == g_seen) return;
    g_seen = gen;
    ::EnumWindows(EnumWindowsApply, 0);
}

// SetWindowsHookEx(WH_CALLWNDPROC) — fires for every Send-class delivery.
// We can't drop the message here (WH_CALLWNDPROC is observation-only),
// but it's an excellent place to check whether our state has changed and
// to install/refresh subclasses lazily on any window touch.
extern "C" __declspec(dllexport) LRESULT CALLBACK
WinternalShieldHookProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) ApplyIfChanged();
    return ::CallNextHookEx(nullptr, code, wp, lp);
}

// SetWindowsHookEx(WH_CBT) — fires BEFORE the kernel commits a window
// create. Returning non-zero from HCBT_CREATEWND aborts; CreateWindow{,Ex}
// returns NULL. This is the documented "block window creation" path; no
// process-level injection beyond what SetWindowsHookEx already provides.
extern "C" __declspec(dllexport) LRESULT CALLBACK
WinternalShieldCbtProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HCBT_CREATEWND) {
        if (CreateMatchesRule((CBT_CREATEWNDW*)lp)) {
            // Abort the create. Caller's CreateWindowExW returns NULL.
            return 1;
        }
    }
    return ::CallNextHookEx(nullptr, code, wp, lp);
}

BOOL APIENTRY DllMain(HMODULE /*hMod*/, DWORD reason, LPVOID /*resv*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_map = ::OpenFileMappingW(FILE_MAP_READ, FALSE, WINTERNAL_SHIELD_MAP_NAME);
        if (g_map) {
            g_st = (ShieldState*)::MapViewOfFile(g_map, FILE_MAP_READ,
                                                  0, 0, sizeof(ShieldState));
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_st) { ::UnmapViewOfFile(g_st); g_st = nullptr; }
        if (g_map) { ::CloseHandle(g_map); g_map = nullptr; }
    }
    return TRUE;
}
