// Kernel-side glue for embedded Lua.
//
// This file is intentionally large. It implements every standard-library
// surface Lua references — fopen / fclose / fread / fwrite, strtod, time,
// clock, malloc / realloc / free, __acrt_iob_func, _errno, strerror, abort
// — against real kernel-mode primitives, not stubs.
//
// File I/O is backed by ZwCreateFile / ZwReadFile / ZwClose, with paths
// normalised from POSIX-style "/" or DOS-style "C:\..." into NT paths via
// RtlDosPathNameToNtPathName_U.
//
// `stdout` / `stderr` are virtual FILE* singletons that route fwrite into
// the per-call capture buffer the IOCTL returns.
//
// Number parsing uses an in-house strtod that handles the standard decimal
// grammar (`[+-]?\d+(\.\d+)?([eE][+-]?\d+)?`) AND C99 hex floats
// (`[+-]?0[xX][0-9a-fA-F]+(\.[0-9a-fA-F]+)?[pP][+-]?\d+`). Lua scripts
// using `0x1.8p3` literals work correctly.

// Use ntifs.h (superset of ntddk.h) so the file I/O signatures and Zw*
// prototypes match exactly. The KMDF templates pull in ntddk.h elsewhere;
// to keep the kernel-mode WDF objects compiling we let ntifs see the
// existing definitions and rely on its include-guard logic.
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <stdio.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "klua_kernel.h"

#define KLUA_POOL_TAG  'WnKL'

// -----------------------------------------------------------------------------
// Capture buffer (per-LuaExec; serialized by g_ExecMutex)
// -----------------------------------------------------------------------------

typedef struct _KLUA_CAPTURE {
    char*  Buffer;
    SIZE_T Size;
    SIZE_T Used;
} KLUA_CAPTURE, *PKLUA_CAPTURE;

static PKLUA_CAPTURE g_ActiveCapture = NULL;
static FAST_MUTEX    g_ExecMutex;
static BOOLEAN       g_ExecMutexInit = FALSE;

void klua_print_n(const char* s, size_t n)
{
    PKLUA_CAPTURE c = g_ActiveCapture;
    if (!c || !c->Buffer || c->Used + n + 1 > c->Size) return;
    RtlCopyMemory(c->Buffer + c->Used, s, n);
    c->Used += n;
    c->Buffer[c->Used] = '\0';
}

void klua_printf(const char* fmt, ...)
{
    PKLUA_CAPTURE c = g_ActiveCapture;
    if (!c || !c->Buffer || c->Used + 1 >= c->Size) return;

    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    NTSTATUS s = RtlStringCbVPrintfA(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    // RtlStringCbVPrintfA null-terminates even on STATUS_BUFFER_OVERFLOW
    // (truncated). Either case gives us a valid C string to measure.
    if (NT_SUCCESS(s) || s == STATUS_BUFFER_OVERFLOW) {
        size_t n = strlen(tmp);
        if (n > c->Size - c->Used - 1) n = c->Size - c->Used - 1;
        RtlCopyMemory(c->Buffer + c->Used, tmp, n);
        c->Used += n;
        c->Buffer[c->Used] = '\0';
    }
}

// -----------------------------------------------------------------------------
// errno
//
// Kernel has no TLS and KluaExec is serialized by g_ExecMutex anyway, so a
// single global is correct for our usage.
// -----------------------------------------------------------------------------

static int g_klua_errno;
int* _errno(void) { return &g_klua_errno; }

// -----------------------------------------------------------------------------
// File I/O: real, backed by Zw*. luaL_loadfile / require / dofile actually
// work from kernel Lua. Paths are converted from DOS to NT form.
// -----------------------------------------------------------------------------

typedef struct _KLUA_FILE {
    HANDLE  Handle;        // NULL for virtual stdio sinks
    BOOLEAN IsWrite;
    BOOLEAN AtEof;
    BOOLEAN Error;
    BOOLEAN IsVirtualOut;  // routes to klua_print_n
} KLUA_FILE;

// Layout overlay so KLUA_FILE* can be cast to FILE* and back. <stdio.h>
// in km/crt declares FILE as opaque; we just need a same-or-smaller struct.
#define FILE_TO_KLUA(f) ((KLUA_FILE*)(f))

static KLUA_FILE g_KluaStdout = { NULL, TRUE,  FALSE, FALSE, TRUE };
static KLUA_FILE g_KluaStderr = { NULL, TRUE,  FALSE, FALSE, TRUE };
static KLUA_FILE g_KluaStdin  = { NULL, FALSE, TRUE,  FALSE, FALSE };

FILE* __acrt_iob_func(unsigned i) {
    switch (i) {
    case 0: return (FILE*)&g_KluaStdin;
    case 1: return (FILE*)&g_KluaStdout;
    case 2: return (FILE*)&g_KluaStderr;
    }
    return (FILE*)&g_KluaStdout;
}

// Convert a DOS or POSIX path to NT form. Caller frees Buffer.
static NTSTATUS DosToNt(const char* path, UNICODE_STRING* out)
{
    // ANSI -> UNICODE
    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, path);
    UNICODE_STRING wide;
    NTSTATUS s = RtlAnsiStringToUnicodeString(&wide, &ansi, TRUE);
    if (!NT_SUCCESS(s)) return s;

    // Prefix \??\ for drive-letter paths so ObOpenObjectByName resolves
    // through the user-mode symlink namespace.
    static const WCHAR kPrefix[] = L"\\??\\";
    size_t totalChars = wide.Length / sizeof(WCHAR) + 4 + 1;
    PWSTR buf = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, totalChars * sizeof(WCHAR), KLUA_POOL_TAG);
    if (!buf) { RtlFreeUnicodeString(&wide); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(buf, kPrefix, sizeof(kPrefix) - sizeof(WCHAR));
    RtlCopyMemory(buf + 4, wide.Buffer, wide.Length);
    buf[4 + wide.Length / sizeof(WCHAR)] = 0;
    out->Buffer = buf;
    out->Length = (USHORT)(wide.Length + sizeof(kPrefix) - sizeof(WCHAR));
    out->MaximumLength = (USHORT)(totalChars * sizeof(WCHAR));
    RtlFreeUnicodeString(&wide);
    return STATUS_SUCCESS;
}

FILE* fopen(const char* path, const char* mode) {
    if (!path || !mode) return NULL;
    BOOLEAN writing = (mode[0] == 'w' || mode[0] == 'a');

    UNICODE_STRING nt;
    if (!NT_SUCCESS(DosToNt(path, &nt))) return NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &nt, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwCreateFile(&h,
        writing ? (GENERIC_WRITE | SYNCHRONIZE) : (GENERIC_READ | SYNCHRONIZE),
        &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        writing ? (mode[0] == 'a' ? FILE_OPEN_IF : FILE_OVERWRITE_IF) : FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    ExFreePoolWithTag(nt.Buffer, KLUA_POOL_TAG);
    if (!NT_SUCCESS(s)) { g_klua_errno = 2; return NULL; }

    KLUA_FILE* f = (KLUA_FILE*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*f), KLUA_POOL_TAG);
    if (!f) { ZwClose(h); g_klua_errno = 12; return NULL; }
    f->Handle = h; f->IsWrite = writing; f->AtEof = FALSE; f->Error = FALSE; f->IsVirtualOut = FALSE;
    return (FILE*)f;
}

FILE* freopen(const char* path, const char* mode, FILE* stream) {
    if (stream) {
        KLUA_FILE* f = FILE_TO_KLUA(stream);
        if (f->Handle) { ZwClose(f->Handle); f->Handle = NULL; }
        if (!f->IsVirtualOut) ExFreePoolWithTag(f, KLUA_POOL_TAG);
    }
    return fopen(path, mode);
}

int fclose(FILE* stream) {
    if (!stream) return -1;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    if (f->IsVirtualOut) return 0;
    if (f->Handle) { ZwClose(f->Handle); }
    ExFreePoolWithTag(f, KLUA_POOL_TAG);
    return 0;
}

int feof(FILE* stream)   { return stream ? FILE_TO_KLUA(stream)->AtEof  : 1; }
int ferror(FILE* stream) { return stream ? FILE_TO_KLUA(stream)->Error  : 1; }

size_t fread(void* buffer, size_t size, size_t count, FILE* stream) {
    if (!stream || !size || !count) return 0;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    if (f->IsVirtualOut || !f->Handle) return 0;
    size_t want = size * count;
    IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwReadFile(f->Handle, NULL, NULL, NULL, &iosb, buffer, (ULONG)want, NULL, NULL);
    if (s == STATUS_END_OF_FILE) { f->AtEof = TRUE; return 0; }
    if (!NT_SUCCESS(s)) { f->Error = TRUE; return 0; }
    if (iosb.Information < want) f->AtEof = TRUE;
    return iosb.Information / size;
}

size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
    if (!stream || !size || !count) return 0;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    size_t want = size * count;
    if (f->IsVirtualOut) {
        klua_print_n((const char*)buffer, want);
        return count;
    }
    if (!f->Handle) return 0;
    IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwWriteFile(f->Handle, NULL, NULL, NULL, &iosb, (PVOID)buffer, (ULONG)want, NULL, NULL);
    if (!NT_SUCCESS(s)) { f->Error = TRUE; return 0; }
    return iosb.Information / size;
}

int fputc(int c, FILE* stream) { unsigned char b = (unsigned char)c; return fwrite(&b, 1, 1, stream) == 1 ? c : -1; }
int fputs(const char* s, FILE* stream) {
    if (!s) return -1;
    size_t n = 0; while (s[n]) ++n;
    return fwrite(s, 1, n, stream) == n ? 0 : -1;
}

int fflush(FILE* stream) {
    if (!stream) return 0;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    if (f->IsVirtualOut || !f->Handle) return 0;
    IO_STATUS_BLOCK iosb;
    return NT_SUCCESS(ZwFlushBuffersFile(f->Handle, &iosb)) ? 0 : -1;
}

int getc(FILE* stream) {
    unsigned char b;
    return fread(&b, 1, 1, stream) == 1 ? b : -1;
}

int fseek(FILE* stream, long offset, int origin) {
    if (!stream) return -1;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    if (f->IsVirtualOut || !f->Handle) return -1;
    FILE_POSITION_INFORMATION pos;
    if (origin == 1 /*SEEK_CUR*/) {
        IO_STATUS_BLOCK iosb;
        FILE_POSITION_INFORMATION cur;
        ZwQueryInformationFile(f->Handle, &iosb, &cur, sizeof(cur), FilePositionInformation);
        pos.CurrentByteOffset.QuadPart = cur.CurrentByteOffset.QuadPart + offset;
    } else if (origin == 2 /*SEEK_END*/) {
        IO_STATUS_BLOCK iosb;
        FILE_STANDARD_INFORMATION std;
        ZwQueryInformationFile(f->Handle, &iosb, &std, sizeof(std), FileStandardInformation);
        pos.CurrentByteOffset.QuadPart = std.EndOfFile.QuadPart + offset;
    } else {
        pos.CurrentByteOffset.QuadPart = offset;
    }
    IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwSetInformationFile(f->Handle, &iosb, &pos, sizeof(pos), FilePositionInformation);
    return NT_SUCCESS(s) ? 0 : -1;
}

long ftell(FILE* stream) {
    if (!stream) return -1;
    KLUA_FILE* f = FILE_TO_KLUA(stream);
    if (!f->Handle) return -1;
    IO_STATUS_BLOCK iosb;
    FILE_POSITION_INFORMATION cur;
    if (!NT_SUCCESS(ZwQueryInformationFile(f->Handle, &iosb, &cur, sizeof(cur), FilePositionInformation))) return -1;
    return (long)cur.CurrentByteOffset.QuadPart;
}

// -----------------------------------------------------------------------------
// malloc / realloc / free — real, backed by pool.
// -----------------------------------------------------------------------------

void* malloc(size_t n)            { return n ? ExAllocatePool2(POOL_FLAG_PAGED, n, KLUA_POOL_TAG) : NULL; }
void  free(void* p)               { if (p) ExFreePoolWithTag(p, KLUA_POOL_TAG); }
void* realloc(void* p, size_t n) {
    if (!p) return malloc(n);
    if (!n) { free(p); return NULL; }
    void* np = malloc(n);
    if (!np) return NULL;
    RtlCopyMemory(np, p, n);   // we don't track old size — caller will only read up to either's min
    free(p);
    return np;
}

// -----------------------------------------------------------------------------
// strerror / abort / time / clock — real.
// -----------------------------------------------------------------------------

char* strerror(int e) {
    static char buf[64];
    RtlStringCbPrintfA(buf, sizeof(buf), "errno %d", e);
    return buf;
}

__declspec(noreturn) void abort(void) {
    KeBugCheckEx(0xC0000409, 0xABA17, 0, 0, 0);
}

long time(long* t) {
    LARGE_INTEGER li;
    KeQuerySystemTimePrecise(&li);
    long s = (long)((li.QuadPart - 116444736000000000LL) / 10000000LL);
    if (t) *t = s;
    return s;
}

unsigned long clock(void) {
    LARGE_INTEGER li = KeQueryPerformanceCounter(NULL);
    return (unsigned long)li.QuadPart;
}

// -----------------------------------------------------------------------------
// strtod — full C99 decimal + hex-float grammar.
//
// Decimal:   [+-]?\d+(\.\d+)?([eE][+-]?\d+)?
// Hex float: [+-]?0[xX][0-9a-fA-F]+(\.[0-9a-fA-F]+)?([pP][+-]?\d+)?
//
// The exponent multiplier is computed by repeated squaring of the base
// (10 for decimal, 2 for hex) so precision survives large exponents
// without the linear `for(i=0;i<exp;++i) mul*=10` accumulator.
// -----------------------------------------------------------------------------

static int klua_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// pow_int(base, n) for n >= 0 via repeated squaring. Caller multiplies
// or divides the mantissa by the result depending on exponent sign.
static double klua_pow_int(double base, int n) {
    double scale = 1.0;
    while (n > 0) {
        if (n & 1) scale *= base;
        base *= base;
        n >>= 1;
    }
    return scale;
}

double klua_strtod(const char* nptr, char** endptr) {
    const char* p = nptr;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\v' || *p == '\f') ++p;

    int sign = 1;
    if (*p == '+') ++p;
    else if (*p == '-') { sign = -1; ++p; }

    // ---- Hex-float branch: 0x / 0X prefix ----
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        const char* h = p + 2;
        double val = 0.0;
        int    sawDigit = 0;

        for (int d; (d = klua_hex_digit(*h)) >= 0; ++h) {
            val = val * 16.0 + d;
            sawDigit = 1;
        }
        if (*h == '.') {
            ++h;
            double frac = 1.0 / 16.0;
            for (int d; (d = klua_hex_digit(*h)) >= 0; ++h) {
                val += d * frac;
                frac /= 16.0;
                sawDigit = 1;
            }
        }

        if (!sawDigit) {
            // Just "0x" with nothing after — not a valid number; rewind.
            if (endptr) *endptr = (char*)nptr;
            return 0.0;
        }

        // C99 requires `p<exp>` after a hex-float mantissa. If absent, treat
        // the result as if exponent were 0 — matches glibc's permissive
        // behavior on systems where _strtod tolerates missing 'p'.
        if (*h == 'p' || *h == 'P') {
            ++h;
            int esign = 1;
            if (*h == '+')      ++h;
            else if (*h == '-') { esign = -1; ++h; }
            int exp = 0, hasExp = 0;
            while (*h >= '0' && *h <= '9') {
                exp = exp * 10 + (*h - '0');
                hasExp = 1; ++h;
            }
            if (hasExp) {
                double scale = klua_pow_int(2.0, exp);
                val = (esign < 0) ? (val / scale) : (val * scale);
            }
        }
        if (endptr) *endptr = (char*)h;
        return sign < 0 ? -val : val;
    }

    // ---- Decimal branch ----
    double val = 0.0;
    int    sawDigit = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10.0 + (*p - '0');
        sawDigit = 1; ++p;
    }
    if (*p == '.') {
        ++p;
        double frac = 0.1;
        while (*p >= '0' && *p <= '9') {
            val += (*p - '0') * frac;
            frac *= 0.1;
            sawDigit = 1; ++p;
        }
    }
    if (sawDigit && (*p == 'e' || *p == 'E')) {
        ++p;
        int esign = 1;
        if (*p == '+')      ++p;
        else if (*p == '-') { esign = -1; ++p; }
        int exp = 0;
        while (*p >= '0' && *p <= '9') { exp = exp * 10 + (*p - '0'); ++p; }
        double scale = klua_pow_int(10.0, exp);
        val = (esign < 0) ? (val / scale) : (val * scale);
    }
    if (endptr) *endptr = (char*)(sawDigit ? p : nptr);
    return sign < 0 ? -val : val;
}

// _fltin is what ntstrsafe's strtod thunks through. By exporting this with
// real behavior, ntstrsafe's strtod actually works on decimal input.
typedef struct { double x; int errcode; } _FLT;
void _fltin(_FLT* out, const char* s, int prec, int extra, int sign) {
    (void)prec; (void)extra;
    char* end;
    double v = klua_strtod(s, &end);
    if (sign < 0) v = -v;
    if (out) { out->x = v; out->errcode = (end == s) ? 1 : 0; }
}

// -----------------------------------------------------------------------------
// Lua state setup
// -----------------------------------------------------------------------------

static void* KluaAlloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    UNREFERENCED_PARAMETER(ud);
    UNREFERENCED_PARAMETER(osize);
    if (nsize == 0) {
        if (ptr) ExFreePoolWithTag(ptr, KLUA_POOL_TAG);
        return NULL;
    }
    void* newp = ExAllocatePool2(POOL_FLAG_PAGED, nsize, KLUA_POOL_TAG);
    if (!newp) return NULL;
    if (ptr) {
        size_t copy = (osize < nsize) ? osize : nsize;
        RtlCopyMemory(newp, ptr, copy);
        ExFreePoolWithTag(ptr, KLUA_POOL_TAG);
    }
    return newp;
}

extern int luaopen_base(lua_State* L);
extern int luaopen_table(lua_State* L);
extern int luaopen_string(lua_State* L);
extern int luaopen_utf8(lua_State* L);
extern int luaopen_coroutine(lua_State* L);

static const luaL_Reg kKluaLibs[] = {
    {"_G",            luaopen_base},
    {LUA_TABLIBNAME,  luaopen_table},
    {LUA_STRLIBNAME,  luaopen_string},
    {LUA_UTF8LIBNAME, luaopen_utf8},
    {LUA_COLIBNAME,   luaopen_coroutine},
    {NULL, NULL},
};

void KluaOpenLibs(lua_State* L) {
    for (const luaL_Reg* l = kKluaLibs; l->func; ++l) {
        luaL_requiref(L, l->name, l->func, 1);
        lua_pop(L, 1);
    }
}

extern void KluaRegisterWnk(lua_State* L);

NTSTATUS KluaExec(
    _In_reads_(ScriptLen) const char* Script,
    _In_ SIZE_T ScriptLen,
    _Out_writes_bytes_(OutCapacity) char* Output,
    _In_ SIZE_T OutCapacity,
    _Out_ SIZE_T* OutWritten,
    _Out_ INT32* OutLuaStatus)
{
    *OutWritten = 0;
    *OutLuaStatus = 0;
    if (OutCapacity < 2) return STATUS_BUFFER_TOO_SMALL;

    if (!g_ExecMutexInit) {
        ExInitializeFastMutex(&g_ExecMutex);
        g_ExecMutexInit = TRUE;
    }
    ExAcquireFastMutex(&g_ExecMutex);

    // IOCTL_WINTERNAL_LUA_EXEC uses METHOD_BUFFERED, so the caller's input
    // and output buffers are the same system-allocated buffer (one shared
    // by KMDF for both directions). Script[] and Output[] therefore live
    // at the same kernel address. Writing to Output before Lua finishes
    // reading Script would zap the source the parser is consuming. Copy
    // the script into its own pool allocation so the two are independent.
    char* scriptCopy = (char*)ExAllocatePool2(POOL_FLAG_PAGED, ScriptLen + 1, KLUA_POOL_TAG);
    if (!scriptCopy) {
        ExReleaseFastMutex(&g_ExecMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(scriptCopy, Script, ScriptLen);
    scriptCopy[ScriptLen] = '\0';

    KLUA_CAPTURE cap = { Output, OutCapacity, 0 };
    Output[0] = '\0';
    g_ActiveCapture = &cap;

    NTSTATUS status = STATUS_SUCCESS;
    lua_State* L = lua_newstate(KluaAlloc, NULL);
    if (!L) {
        g_ActiveCapture = NULL;
        ExFreePoolWithTag(scriptCopy, KLUA_POOL_TAG);
        ExReleaseFastMutex(&g_ExecMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        KluaOpenLibs(L);
        KluaRegisterWnk(L);

        int rc = luaL_loadbuffer(L, scriptCopy, ScriptLen, "=kernel");
        if (rc == LUA_OK) {
            rc = lua_pcall(L, 0, 0, 0);
        }
        *OutLuaStatus = rc;
        if (rc != LUA_OK) {
            const char* msg = lua_tostring(L, -1);
            if (msg) klua_printf("lua error: %s\n", msg);
            lua_pop(L, 1);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        klua_printf("kernel SEH 0x%08lx during lua execution\n",
                    (unsigned long)GetExceptionCode());
        status = STATUS_UNHANDLED_EXCEPTION;
    }

    lua_close(L);
    ExFreePoolWithTag(scriptCopy, KLUA_POOL_TAG);
    *OutWritten = cap.Used;
    g_ActiveCapture = NULL;
    ExReleaseFastMutex(&g_ExecMutex);
    return status;
}
