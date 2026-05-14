// WClap — a small, clap-inspired argument parser for C++.
//
// Original implementation (not a port). Modeled after Rust's clap in API
// shape only — App holds Arg + subcommand specs; parse() returns a Match
// you query with present() / value() / sub_match(). Auto-generates --help.
//
// Scope: subcommands, positional args (multi-positional via positional_multi),
// named flags (--flag), value flags (--key=val, --key val, -k val), short
// flags. Validation: required/optional, default values. Wide-char throughout
// to match Winternal CLI's wmain.
//
// Design choices vs. clap:
//   * Single-header. No exceptions.
//   * --help / -h prints and exits(0) — matches clap's terminating help.
//   * Unknown args print to stderr and exit(2). Required-missing same.
//   * No fancy validators, no global args, no flatten/group. Add later if needed.

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <cstdio>
#include <cstdlib>
#include <io.h>
#include <Windows.h>

namespace wclap {

// --- ANSI styling -----------------------------------------------------
//
// SGR escape codes (ECMA-48). Enabled if stdout/stderr is a real console
// AND ENABLE_VIRTUAL_TERMINAL_PROCESSING is supported. NO_COLOR env var
// forces off. Caller can also override at runtime.
//
// Palette inspired by clap's help formatter — bold cyan headers, bold
// option names, yellow value placeholders, dim help text.

// Real terminal width via VT escape — ConPTY (Windows Terminal, VS Code)
// caps GetConsoleScreenBufferInfo().dwSize.X at 100 regardless of the
// hosting terminal's actual size, so we ask the terminal directly.
//
// Sends ESC[18t (XTerm "Report text area size in characters"). The
// terminal responds on stdin with ESC[8;<rows>;<cols>t. We read with a
// short timeout and parse out <cols>. Returns 0 if anything fails
// (stdin not a console, terminal didn't respond, etc.).
inline int query_vt_width() {
    HANDLE hOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn  = ::GetStdHandle(STD_INPUT_HANDLE);
    if (!hOut || hOut == INVALID_HANDLE_VALUE) return 0;
    if (!hIn  || hIn  == INVALID_HANDLE_VALUE) return 0;
    // No GetFileType pre-check: ConPTY presents stdout/stdin as FILE_TYPE_PIPE
    // even when routed through a real terminal. We rely on GetConsoleMode
    // below (only succeeds on console handles) and the 100ms read timeout to
    // safely bail when there's no terminal on the other end. NOTE: pwsh 7
    // redirects child handles through pipes by default, so GetConsoleMode
    // will fail there — users who want wide rendering in pwsh 7 should set
    // $env:COLUMNS = $Host.UI.RawUI.WindowSize.Width.

    DWORD oldOut = 0, oldIn = 0;
    if (!::GetConsoleMode(hOut, &oldOut)) return 0;
    if (!::GetConsoleMode(hIn,  &oldIn))  return 0;

    // VT out, raw + VT in. Disabling line input makes ReadConsoleInput
    // deliver key records as fast as the terminal sends them.
    if (!::SetConsoleMode(hOut, oldOut | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/)) return 0;
    DWORD inWanted = (oldIn & ~(0x0002 /*ENABLE_LINE_INPUT*/ | 0x0004 /*ENABLE_ECHO_INPUT*/))
                   | 0x0200 /*ENABLE_VIRTUAL_TERMINAL_INPUT*/;
    if (!::SetConsoleMode(hIn, inWanted)) {
        ::SetConsoleMode(hOut, oldOut);
        return 0;
    }
    ::FlushConsoleInputBuffer(hIn);

    const char* query = "\x1b[18t";
    DWORD written = 0;
    ::WriteFile(hOut, query, (DWORD)5, &written, nullptr);

    // Drain response into a small buffer. We expect ~12 bytes back; bail
    // after 100ms in case the terminal doesn't support DECRQTPARM-style
    // window manipulation queries.
    char buf[64] = {};
    DWORD got = 0;
    const DWORD start = ::GetTickCount();
    while (got < sizeof(buf) - 1) {
        DWORD remaining = 100 - (::GetTickCount() - start);
        if ((int)remaining <= 0) break;
        DWORD wait = ::WaitForSingleObject(hIn, remaining);
        if (wait != WAIT_OBJECT_0) break;
        INPUT_RECORD rec;
        DWORD readN = 0;
        if (!::ReadConsoleInputW(hIn, &rec, 1, &readN) || readN == 0) break;
        // Key down records carry the bytes the terminal sent us.
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            wchar_t wc = rec.Event.KeyEvent.uChar.UnicodeChar;
            if (wc) {
                buf[got++] = (char)wc;
                if (wc == L't' || wc == L'R') break;
            }
        }
    }
    ::SetConsoleMode(hOut, oldOut);
    ::SetConsoleMode(hIn,  oldIn);

    // Parse "ESC [ 8 ; <rows> ; <cols> t".
    for (DWORD i = 0; i + 4 < got; ++i) {
        if (buf[i] == 0x1b && buf[i+1] == '[' && buf[i+2] == '8' && buf[i+3] == ';') {
            const char* p = buf + i + 4;
            while (*p && *p != ';' && *p != 't') ++p;
            if (*p != ';') return 0;
            int cols = atoi(p + 1);
            return cols > 0 ? cols : 0;
        }
    }
    return 0;
}

namespace style {
    inline bool& enabled() { static bool e = false; return e; }
    inline bool& initialized() { static bool i = false; return i; }

    inline void init() {
        if (initialized()) return;
        initialized() = true;
        wchar_t* nc = nullptr;
        size_t ncLen = 0;
        if (_wdupenv_s(&nc, &ncLen, L"NO_COLOR") == 0 && nc) { free(nc); enabled() = false; return; }
        if (nc) free(nc);
        HANDLE h = ::GetStdHandle(STD_ERROR_HANDLE);
        if (h == INVALID_HANDLE_VALUE) return;
        DWORD mode = 0;
        if (!::GetConsoleMode(h, &mode)) return;
        if (::SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/)) {
            enabled() = true;
        }
    }
    inline void force(bool on) { initialized() = true; enabled() = on; }

    inline const wchar_t* RESET()     { return enabled() ? L"\x1b[0m"   : L""; }
    inline const wchar_t* BOLD()      { return enabled() ? L"\x1b[1m"   : L""; }
    inline const wchar_t* DIM()       { return enabled() ? L"\x1b[2m"   : L""; }
    inline const wchar_t* UNDERLINE() { return enabled() ? L"\x1b[4m"   : L""; }
    inline const wchar_t* CYAN()      { return enabled() ? L"\x1b[36m"  : L""; }
    inline const wchar_t* YELLOW()    { return enabled() ? L"\x1b[33m"  : L""; }
    inline const wchar_t* GREEN()     { return enabled() ? L"\x1b[32m"  : L""; }
    inline const wchar_t* MAGENTA()   { return enabled() ? L"\x1b[35m"  : L""; }
}

class App;
class Match;

class Arg {
public:
    explicit Arg(std::wstring name) : name_(std::move(name)) {}

    Arg& short_name(wchar_t c)             { short_ = c; return *this; }
    Arg& long_name(std::wstring n)         { long_ = std::move(n); return *this; }
    Arg& help(std::wstring h)              { help_ = std::move(h); return *this; }
    Arg& takes_value(bool v = true)        { takes_value_ = v; return *this; }
    Arg& required(bool r = true)           { required_ = r; return *this; }
    // Positional args are matched by their order on the command line.
    Arg& positional()                      { positional_ = true; takes_value_ = true; return *this; }
    // Positional that captures all remaining unparsed args.
    Arg& positional_multi()                { positional_ = true; takes_value_ = true; multi_ = true; return *this; }
    Arg& default_value(std::wstring v)     { default_ = std::move(v); takes_value_ = true; return *this; }

    const std::wstring& name() const { return name_; }

private:
    std::wstring name_;
    wchar_t      short_ = 0;
    std::wstring long_;
    std::wstring help_;
    std::optional<std::wstring> default_;
    bool takes_value_ = false;
    bool required_    = false;
    bool positional_  = false;
    bool multi_       = false;
    friend class App;
    friend class Match;
};

class Match {
public:
    bool present(std::wstring_view name) const {
        return flags_.count(std::wstring(name)) > 0;
    }
    std::optional<std::wstring> value(std::wstring_view name) const {
        auto it = values_.find(std::wstring(name));
        if (it == values_.end()) return std::nullopt;
        return it->second;
    }
    // Convenience: get an integer (decimal or 0x-hex). Returns nullopt if
    // absent OR unparseable.
    std::optional<uint64_t> value_u64(std::wstring_view name) const {
        auto s = value(name);
        if (!s) return std::nullopt;
        const wchar_t* p = s->c_str();
        int base = 10;
        if (s->size() > 2 && (s->starts_with(L"0x") || s->starts_with(L"0X"))) { p += 2; base = 16; }
        wchar_t* end = nullptr;
        uint64_t v = wcstoull(p, &end, base);
        if (!end || *end) return std::nullopt;
        return v;
    }
    const std::vector<std::wstring>& many(std::wstring_view name) const {
        static const std::vector<std::wstring> empty;
        auto it = many_.find(std::wstring(name));
        return it == many_.end() ? empty : it->second;
    }
    const std::wstring& sub_name() const { return sub_name_; }
    const Match* sub_match() const { return sub_.get(); }

private:
    std::unordered_set<std::wstring> flags_;
    std::unordered_map<std::wstring, std::wstring> values_;
    std::unordered_map<std::wstring, std::vector<std::wstring>> many_;
    std::wstring sub_name_;
    std::unique_ptr<Match> sub_;
    friend class App;
};

class App {
public:
    explicit App(std::wstring name) : name_(std::move(name)) {}

    App& about(std::wstring a)             { about_ = std::move(a); return *this; }
    App& version(std::wstring v)           { version_ = std::move(v); return *this; }
    App& arg(Arg a)                        { args_.push_back(std::move(a)); return *this; }
    App& subcommand(App sub)               { subs_.push_back(std::move(sub)); return *this; }
    // Replace the bare command name in --help with a richer left-column
    // string (typically the command name plus inline arg/flag hints). The
    // bare name_ is still what dispatch matches against.
    App& display(std::wstring d)           { display_ = std::move(d); return *this; }
    // Group subcommands under a named section in --help. Subs with the same
    // heading render together; first-occurrence order is preserved. Subs
    // without a heading go into the default "Commands" group.
    App& help_heading(std::wstring h)      { help_heading_ = std::move(h); return *this; }

    // Parse argv excluding argv[0]. Caller passes argc-1, argv+1 or already-
    // stripped position. On --help / parse error, prints + exits.
    Match parse(int argc, wchar_t** argv) {
        Match m;
        if (!parse_impl(argc, argv, m)) std::exit(2);
        return m;
    }

    void print_help(FILE* out = stderr) const {
        style::init();
        const wchar_t* B = style::BOLD();
        const wchar_t* U = style::UNDERLINE();
        const wchar_t* Y = style::YELLOW();
        const wchar_t* C = style::CYAN();
        const wchar_t* R = style::RESET();

        // Terminal width — probe in order of accuracy:
        //   1. $COLUMNS env var (user/shell override).
        //   2. VT ESC[18t query — works through ConPTY (Windows Terminal,
        //      VS Code, etc.), which clamps GetConsoleScreenBufferInfo to
        //      a fixed internal buffer (often 100) regardless of real size.
        //   3. GetConsoleScreenBufferInfo — fallback for legacy conhost or
        //      when stdin isn't a tty so we can't read a VT response.
        //   4. 100 — final fallback (piped output, etc).
        // Floor at 40 so wrapping math stays sane on absurdly narrow terms;
        // no upper cap — let wide terminals breathe.
        int term_w = 0;
        {
            wchar_t* cols = nullptr; size_t cl = 0;
            if (_wdupenv_s(&cols, &cl, L"COLUMNS") == 0 && cols) {
                wchar_t* end = nullptr;
                long v = wcstol(cols, &end, 10);
                if (end && *end == 0 && v > 0) term_w = (int)v;
                free(cols);
            }
        }
        if (term_w <= 0) term_w = query_vt_width();
        if (term_w <= 0) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            DWORD probe[2] = { (DWORD)(out == stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE),
                               (DWORD)(out == stdout ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE) };
            for (DWORD which : probe) {
                HANDLE h = ::GetStdHandle(which);
                if (!h || h == INVALID_HANDLE_VALUE) continue;
                if (!::GetConsoleScreenBufferInfo(h, &csbi)) continue;
                int bw = csbi.dwSize.X;
                int ww = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                if (bw > 0 && bw <= 1000) { term_w = bw; break; }
                if (ww > 0)               { term_w = ww; break; }
            }
        }
        if (term_w <= 0) term_w = 100;
        if (term_w < 40) term_w = 40;

        if (!about_.empty()) fwprintf(out, L"%ls\n\n", about_.c_str());

        // Usage line: prog [OPTIONS] <POS>... <COMMAND>
        fwprintf(out, L"%ls%lsUsage:%ls %ls%ls%ls", B, U, R, B, name_.c_str(), R);
        bool anyFlag = false;
        for (auto& a : args_) if (!a.positional_) { anyFlag = true; break; }
        if (anyFlag) fwprintf(out, L" [OPTIONS]");
        for (auto& a : args_) {
            if (!a.positional_) continue;
            std::wstring up = upper(a.name_);
            if (a.required_) fwprintf(out, L" <%ls>", up.c_str());
            else             fwprintf(out, L" [%ls]%ls", up.c_str(), a.multi_ ? L"..." : L"");
        }
        if (!subs_.empty()) fwprintf(out, L" <COMMAND>");
        fwprintf(out, L"\n\n");

        // Build the entry table once so we can compute a unified left-column
        // width across all sections (matches clap's layout).
        auto positionals_v = build_pos_entries(B, Y, R);
        auto options_v     = build_opt_entries(B, Y, R);

        // Subcommands: grouped by help_heading, first-appearance order.
        std::vector<std::wstring> sub_group_order;
        std::unordered_map<std::wstring, std::vector<Entry>> sub_groups;
        for (auto& s : subs_) {
            std::wstring h = s.help_heading_.empty() ? std::wstring(L"Commands") : s.help_heading_;
            if (sub_groups.find(h) == sub_groups.end()) sub_group_order.push_back(h);
            Entry e;
            const std::wstring& label = s.display_.empty() ? s.name_ : s.display_;
            e.left = std::wstring(C) + label + R;
            e.leftLen = label.size();
            e.desc = s.about_;
            sub_groups[h].push_back(std::move(e));
        }

        size_t left_w = 0;
        for (auto& e : positionals_v) if (e.leftLen > left_w) left_w = e.leftLen;
        for (auto& e : options_v)     if (e.leftLen > left_w) left_w = e.leftLen;
        for (auto& h : sub_group_order)
            for (auto& e : sub_groups[h]) if (e.leftLen > left_w) left_w = e.leftLen;
        // Cap the left column proportionally to the terminal so descriptions
        // always get a fair share. Entries longer than the cap overflow onto
        // a second line. Floor at 20 cols so the cap isn't useless on tiny
        // terminals; otherwise scale ~50% of the available width.
        size_t cap = (size_t)term_w / 2;
        if (cap < 20) cap = 20;
        if (left_w > cap) left_w = cap;

        const size_t indent   = 2;
        const size_t gap      = 2;
        const size_t desc_col = indent + left_w + gap;
        const size_t desc_w   = (size_t)term_w > desc_col + 20 ? (size_t)term_w - desc_col : 20;

        print_section(out, B, U, R, L"Arguments", positionals_v, indent, left_w, gap, desc_col, desc_w);
        print_section(out, B, U, R, L"Options",   options_v,     indent, left_w, gap, desc_col, desc_w);
        for (auto& h : sub_group_order) {
            print_section(out, B, U, R, h.c_str(), sub_groups[h], indent, left_w, gap, desc_col, desc_w);
        }
    }

private:
    struct Entry { std::wstring left; size_t leftLen; std::wstring desc; };

    static std::wstring upper(const std::wstring& s) {
        std::wstring o; o.reserve(s.size());
        for (wchar_t c : s) o.push_back((wchar_t)towupper(c));
        return o;
    }

    std::vector<Entry> build_pos_entries(const wchar_t* B, const wchar_t* Y, const wchar_t* R) const {
        std::vector<Entry> v;
        for (auto& a : args_) {
            if (!a.positional_) continue;
            Entry e;
            std::wstring up = upper(a.name_);
            e.left = std::wstring(B) + L"<" + up + L">" + R;
            e.leftLen = up.size() + 2;
            e.desc = a.help_;
            v.push_back(std::move(e));
        }
        return v;
    }

    std::vector<Entry> build_opt_entries(const wchar_t* B, const wchar_t* Y, const wchar_t* R) const {
        std::vector<Entry> v;
        bool anyShort = false;
        for (auto& a : args_) if (!a.positional_ && a.short_) { anyShort = true; break; }
        // Add user options
        for (auto& a : args_) {
            if (a.positional_) continue;
            Entry e = render_opt(a, anyShort, B, Y, R);
            v.push_back(std::move(e));
        }
        // Auto --help entry, matching clap.
        Entry h;
        if (anyShort) {
            h.left = std::wstring(B) + L"-h" + R + L", " + B + L"--help" + R;
            h.leftLen = 10; // "-h, --help"
        } else {
            h.left = std::wstring(B) + L"--help" + R;
            h.leftLen = 6;
        }
        h.desc = L"Print help";
        v.push_back(std::move(h));
        return v;
    }

    Entry render_opt(const Arg& a, bool anyShort, const wchar_t* B, const wchar_t* Y, const wchar_t* R) const {
        Entry e;
        std::wstring styled, plain;
        if (a.short_) {
            styled += B; styled += L"-"; styled.push_back(a.short_); styled += R;
            plain  += L"-"; plain.push_back(a.short_);
            if (!a.long_.empty()) { styled += L", "; plain += L", "; }
        } else if (anyShort && !a.long_.empty()) {
            // align long-only entries under shorts
            styled += L"    ";
            plain  += L"    ";
        }
        if (!a.long_.empty()) {
            styled += B; styled += L"--"; styled += a.long_; styled += R;
            plain  += L"--"; plain  += a.long_;
        }
        if (a.takes_value_) {
            std::wstring up = upper(a.name_);
            styled += L" "; styled += Y; styled += L"<"; styled += up; styled += L">"; styled += R;
            plain  += L" <"; plain  += up; plain  += L">";
        }
        e.left = std::move(styled);
        e.leftLen = plain.size();
        e.desc = a.help_;
        return e;
    }

    static void print_section(FILE* out, const wchar_t* B, const wchar_t* U, const wchar_t* R,
                              const wchar_t* title, std::vector<Entry>& entries,
                              size_t indent, size_t left_w, size_t gap,
                              size_t desc_col, size_t desc_w) {
        if (entries.empty()) return;
        fwprintf(out, L"%ls%ls%ls:%ls\n", B, U, title, R);
        for (auto& e : entries) {
            for (size_t k = 0; k < indent; ++k) fputwc(L' ', out);
            fputws(e.left.c_str(), out);
            if (e.leftLen <= left_w) {
                for (size_t k = e.leftLen; k < left_w + gap; ++k) fputwc(L' ', out);
                print_wrapped(out, e.desc, desc_col, desc_w, /*firstHanging=*/false);
            } else {
                // Left overflowed the column: wrap to next line, description fully indented.
                fputwc(L'\n', out);
                print_wrapped(out, e.desc, desc_col, desc_w, /*firstHanging=*/true);
            }
        }
        fputwc(L'\n', out);
    }

    static void print_wrapped(FILE* out, const std::wstring& text,
                              size_t indent_cols, size_t width, bool firstHanging) {
        if (text.empty()) { fputwc(L'\n', out); return; }
        size_t pos = 0;
        bool first = true;
        while (pos < text.size()) {
            if (!first || firstHanging)
                for (size_t k = 0; k < indent_cols; ++k) fputwc(L' ', out);
            first = false;
            size_t remaining = text.size() - pos;
            size_t end = pos + std::min<size_t>(width, remaining);
            if (end < text.size()) {
                size_t b = end;
                while (b > pos && text[b] != L' ') --b;
                if (b > pos + width / 3) end = b; // only break if we're not too far back
            }
            for (size_t k = pos; k < end; ++k) fputwc(text[k], out);
            fputwc(L'\n', out);
            pos = end;
            while (pos < text.size() && text[pos] == L' ') ++pos;
        }
    }

    bool parse_impl(int argc, wchar_t** argv, Match& m) {
        std::vector<Arg*> positionals;
        for (auto& a : args_) if (a.positional_) positionals.push_back(&a);
        size_t pos_at = 0;

        for (int i = 0; i < argc; ++i) {
            std::wstring_view a = argv[i];

            if (a == L"--help" || a == L"-h") {
                print_help(stdout);
                std::exit(0);
            }

            // Subcommand dispatch — first non-flag token tries to match.
            if (!a.empty() && a[0] != L'-' && pos_at == 0) {
                for (auto& sub : subs_) {
                    if (a == sub.name_) {
                        m.sub_name_ = sub.name_;
                        m.sub_ = std::make_unique<Match>();
                        return sub.parse_impl(argc - i - 1, argv + i + 1, *m.sub_);
                    }
                }
            }

            // Long flag
            if (a.size() > 2 && a[0] == L'-' && a[1] == L'-') {
                std::wstring_view rest = a.substr(2);
                std::wstring_view value;
                auto eq = rest.find(L'=');
                bool inline_value = false;
                if (eq != std::wstring_view::npos) {
                    value = rest.substr(eq + 1);
                    rest = rest.substr(0, eq);
                    inline_value = true;
                }
                Arg* arg = find_long(rest);
                if (!arg) {
                    fwprintf(stderr, L"%ls: unknown option --%ls\n", name_.c_str(), std::wstring(rest).c_str());
                    return false;
                }
                m.flags_.insert(arg->name_);
                if (arg->takes_value_) {
                    if (inline_value) {
                        m.values_[arg->name_] = std::wstring(value);
                    } else if (i + 1 < argc) {
                        m.values_[arg->name_] = argv[++i];
                    } else {
                        fwprintf(stderr, L"%ls: --%ls expects a value\n", name_.c_str(), arg->long_.c_str());
                        return false;
                    }
                }
                continue;
            }
            // Short flag
            if (a.size() == 2 && a[0] == L'-' && a[1] != L'-') {
                Arg* arg = find_short(a[1]);
                if (!arg) {
                    fwprintf(stderr, L"%ls: unknown short option %ls\n", name_.c_str(), std::wstring(a).c_str());
                    return false;
                }
                m.flags_.insert(arg->name_);
                if (arg->takes_value_) {
                    if (i + 1 < argc) m.values_[arg->name_] = argv[++i];
                    else {
                        fwprintf(stderr, L"%ls: -%lc expects a value\n", name_.c_str(), a[1]);
                        return false;
                    }
                }
                continue;
            }

            // Positional
            if (pos_at < positionals.size()) {
                Arg* arg = positionals[pos_at];
                m.flags_.insert(arg->name_);
                m.values_[arg->name_] = std::wstring(a);
                if (arg->multi_) {
                    m.many_[arg->name_].emplace_back(a);
                    // multi captures everything else as well
                    while (++i < argc) m.many_[arg->name_].emplace_back(argv[i]);
                } else {
                    ++pos_at;
                }
            } else {
                fwprintf(stderr, L"%ls: extra argument %ls\n", name_.c_str(), std::wstring(a).c_str());
                return false;
            }
        }

        // Apply defaults
        for (auto& arg : args_) {
            if (arg.default_ && !m.values_.count(arg.name_)) {
                m.values_[arg.name_] = *arg.default_;
                m.flags_.insert(arg.name_);
            }
        }
        // Check required
        for (auto& arg : args_) {
            if (arg.required_ && !m.flags_.count(arg.name_)) {
                fwprintf(stderr, L"%ls: required '%ls' was not provided\n",
                         name_.c_str(), arg.name_.c_str());
                print_help(stderr);
                return false;
            }
        }
        return true;
    }

    Arg* find_long(std::wstring_view n) {
        for (auto& a : args_) if (!a.long_.empty() && a.long_ == n) return &a;
        return nullptr;
    }
    Arg* find_short(wchar_t c) {
        for (auto& a : args_) if (a.short_ && a.short_ == c) return &a;
        return nullptr;
    }

    std::wstring name_;
    std::wstring display_;
    std::wstring help_heading_;
    std::wstring about_;
    std::wstring version_;
    std::vector<Arg> args_;
    std::vector<App> subs_;
};

} // namespace wclap
