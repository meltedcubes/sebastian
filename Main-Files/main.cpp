#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using ntflush_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, SIZE_T);

namespace util {

struct handle {
    HANDLE h;
    handle() : h(INVALID_HANDLE_VALUE) {}
    explicit handle(HANDLE x) : h(x) {}
    ~handle() { close(); }
    handle(const handle&) = delete;
    handle& operator=(const handle&) = delete;
    handle(handle&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    handle& operator=(handle&& o) noexcept {
        if (this != &o) { close(); h = o.h; o.h = INVALID_HANDLE_VALUE; }
        return *this;
    }
    HANDLE get() const { return h; }
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
    void close() {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
};

inline uint32_t alignup(uint32_t v, uint32_t a) { return a ? ((v + a - 1) / a) * a : v; }

void vt() {
    HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m = 0;
    if (o != INVALID_HANDLE_VALUE && GetConsoleMode(o, &m))
        SetConsoleMode(o, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

std::wstring towide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

}  // namespace util

namespace con {

constexpr auto R = "\033[31m";
constexpr auto G = "\033[32m";
constexpr auto Y = "\033[33m";
constexpr auto C = "\033[36m";
constexpr auto B = "\033[1m";
constexpr auto X = "\033[0m";

void info(const char* fmt, ...) {
    va_list ap;
    printf("%s%s[ info ]%s ", B, C, X);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void ok(const std::string& s)   { printf("%s%s[ success ]%s %s\n", B, G, X, s.c_str()); }
void fail(const std::string& s) { printf("%s%s[ fail ]%s %s\n", B, R, X, s.c_str()); }
void warn(const std::string& s) { printf("%s%s[ warn ]%s %s\n", B, Y, X, s.c_str()); }

}  // namespace con

namespace proc {

DWORD find(const wchar_t* name) {
    util::handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return 0;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap.get(), &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, name)) return pe.th32ProcessID;
        } while (Process32NextW(snap.get(), &pe));
    }
    return 0;
}

bool mod(HANDLE h, const wchar_t* name, PVOID* base, DWORD* size) {
    util::handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(h)));
    if (!snap) return false;

    MODULEENTRY32W me;
    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap.get(), &me)) {
        do {
            if (!_wcsicmp(me.szModule, name)) {
                *base = me.modBaseAddr;
                *size = me.modBaseSize;
                return true;
            }
        } while (Module32NextW(snap.get(), &me));
    }
    return false;
}

std::vector<MODULEENTRY32W> mods(HANDLE h) {
    std::vector<MODULEENTRY32W> out;
    util::handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(h)));
    if (!snap) return out;

    MODULEENTRY32W me;
    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap.get(), &me)) {
        do { out.push_back(me); } while (Module32NextW(snap.get(), &me));
    }
    return out;
}

std::string path(DWORD pid) {
    util::handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) return {};

    WCHAR buf[MAX_PATH];
    DWORD n = MAX_PATH;
    if (!QueryFullProcessImageNameW(h.get(), 0, buf, &n)) return {};

    std::vector<char> ab(static_cast<size_t>(n) * 4);
    int m = WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(n),
                                ab.data(), static_cast<int>(ab.size()), nullptr, nullptr);
    return std::string(ab.data(), m > 0 ? static_cast<size_t>(m) : 0);
}

}  // namespace proc

namespace mem {

bool readable(HANDLE h, const void* a) {
    MEMORY_BASIC_INFORMATION m;
    return VirtualQueryEx(h, a, &m, sizeof(m)) &&
           m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD) &&
           (m.Protect & 0xFF) != PAGE_NOACCESS;
}

bool exec(HANDLE h, const void* a) {
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQueryEx(h, a, &m, sizeof(m)) || m.State != MEM_COMMIT) return false;
    switch (m.Protect & 0xFF) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

SIZE_T page(HANDLE h, const void* a, SIZE_T n, BYTE* out) {
    SIZE_T r = 0;
    ReadProcessMemory(h, a, out, n, &r);
    return r;
}

template <typename T>
bool read(HANDLE h, const void* a, T* out) {
    SIZE_T n = 0;
    return ReadProcessMemory(h, a, out, sizeof(T), &n) && n == sizeof(T);
}

}  // namespace mem

namespace pe {

struct sec {
    IMAGE_SECTION_HEADER hdr;
    DWORD rva, vsize, raw, rawsz;
    bool  code;
};

std::vector<BYTE> load(const std::string& p) {
    util::handle f(CreateFileW(util::towide(p).c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!f) return {};

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f.get(), &sz) || sz.QuadPart <= 0) return {};

    std::vector<BYTE> b(static_cast<size_t>(sz.QuadPart));
    DWORD rd = 0;
    if (!ReadFile(f.get(), b.data(), static_cast<DWORD>(sz.QuadPart), &rd, nullptr)) return {};
    b.resize(rd);
    return b;
}

PIMAGE_NT_HEADERS nt(std::vector<BYTE>& b) {
    if (b.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(b.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > b.size())
        return nullptr;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(b.data() + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE ? nt : nullptr;
}

std::vector<sec> secs(std::vector<BYTE>& b) {
    std::vector<sec> out;
    auto* hdr = nt(b);
    if (!hdr) return out;

    auto* s = IMAGE_FIRST_SECTION(hdr);
    for (DWORD i = 0; i < hdr->FileHeader.NumberOfSections; i++) {
        sec x{ s[i],
               s[i].VirtualAddress,
               s[i].Misc.VirtualSize,
               s[i].PointerToRawData,
               s[i].SizeOfRawData,
               (s[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0 };
        out.push_back(x);
    }
    return out;
}

void commit(std::vector<BYTE>& b, const std::vector<sec>& all) {
    auto* hdr = nt(b);
    if (!hdr) return;

    auto* s = IMAGE_FIRST_SECTION(hdr);
    for (size_t i = 0; i < all.size() && i < hdr->FileHeader.NumberOfSections; i++)
        s[i] = all[i].hdr;
}

void fixsiz(std::vector<BYTE>& b) {
    auto* hdr = nt(b);
    if (!hdr) return;

    auto* s = IMAGE_FIRST_SECTION(hdr);
    DWORD sa = hdr->OptionalHeader.SectionAlignment ? hdr->OptionalHeader.SectionAlignment : 0x1000;
    DWORD end = 0;
    for (DWORD i = 0; i < hdr->FileHeader.NumberOfSections; i++)
        end = std::max(end, s[i].VirtualAddress + s[i].Misc.VirtualSize);
    hdr->OptionalHeader.SizeOfImage = util::alignup(end, sa);
}

void runnable(std::vector<BYTE>& b, const BYTE* base) {
    auto* hdr = nt(b);
    if (!hdr) return;

    hdr->OptionalHeader.ImageBase = reinterpret_cast<uint64_t>(base);
    hdr->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                                 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
}

}  // namespace pe

namespace imp {

struct entry {
    std::string mod, name;
    DWORD       rva;
};

using exports = std::unordered_map<uint64_t, std::pair<std::string, std::string>>;

std::string modname(const MODULEENTRY32W& m) {
    char b[260] = {};
    WideCharToMultiByte(CP_UTF8, 0, m.szModule, -1, b, sizeof(b), nullptr, nullptr);
    return std::string(b);
}

exports exportmap(HANDLE h) {
    exports map;
    for (const auto& m : proc::mods(h)) {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS nt;
        if (!mem::read(h, m.modBaseAddr, &dos)) continue;
        if (!mem::read(h, reinterpret_cast<const BYTE*>(m.modBaseAddr) + dos.e_lfanew, &nt)) continue;
        if (!nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) continue;

        DWORD er = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD es = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        std::vector<BYTE> ed(es);
        ReadProcessMemory(h, reinterpret_cast<const BYTE*>(m.modBaseAddr) + er, ed.data(), es, nullptr);

        auto* e = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ed.data());
        if (!e->NumberOfFunctions || !e->NumberOfNames) continue;

        auto* names = reinterpret_cast<const DWORD*>(ed.data() + e->AddressOfNames - er);
        auto* funcs = reinterpret_cast<const DWORD*>(ed.data() + e->AddressOfFunctions - er);
        auto* ords  = reinterpret_cast<const WORD*>(ed.data() + e->AddressOfNameOrdinals - er);

        const std::string mn = modname(m);
        for (DWORD i = 0; i < e->NumberOfNames; i++) {
            if (ords[i] >= e->NumberOfFunctions) continue;
            DWORD fr = funcs[ords[i]];
            if (fr >= er && fr < er + es) continue;

            const char* fn = reinterpret_cast<const char*>(ed.data() + names[i] - er);
            map[reinterpret_cast<uint64_t>(m.modBaseAddr) + fr] = { mn, std::string(fn) };
        }
    }
    return map;
}

std::vector<entry> find(const std::vector<BYTE>& b, const exports& map) {
    std::vector<entry> out;
    std::set<uint64_t> seen;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(b.data());
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(b.data() + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return out;
    const auto* s = reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt + 1);

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(s[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;

        DWORD raw = s[i].PointerToRawData;
        DWORD end = raw + std::min(s[i].SizeOfRawData, s[i].Misc.VirtualSize);
        if (end > b.size()) end = static_cast<DWORD>(b.size());
        if (raw >= b.size() || end <= raw) continue;

        for (DWORD p = raw; p + 8 <= end; p += 8) {
            uint64_t v = 0;
            memcpy(&v, b.data() + p, sizeof(v));
            auto it = map.find(v);
            if (it == map.end() || seen.count(v)) continue;

            entry e{ it->second.first, it->second.second, s[i].VirtualAddress + (p - raw) };
            out.push_back(e);
            seen.insert(v);
        }
    }
    return out;
}

bool rebuild(std::vector<BYTE>& b, const std::vector<entry>& imports, DWORD live_irva) {
    if (imports.empty()) { con::warn("no imports to rebuild"); return false; }
    con::info("rebuilding %zu imports...\n", imports.size());

    std::map<std::string, std::vector<entry>> bymod;
    for (const auto& e : imports) bymod[e.mod].push_back(e);

    auto* nt = pe::nt(b);
    if (!nt) return false;

    DWORD fa = nt->OptionalHeader.FileAlignment ? nt->OptionalHeader.FileAlignment : 0x200;
    DWORD sa = nt->OptionalHeader.SectionAlignment ? nt->OptionalHeader.SectionAlignment : 0x1000;
    DWORD descsz = static_cast<DWORD>(bymod.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD iatsz = 0, namesz = 0;
    for (const auto& [m, es] : bymod) {
        iatsz += static_cast<DWORD>((es.size() + 1) * sizeof(uint64_t) * 2);
        namesz += static_cast<DWORD>(m.size() + 1);
        for (const auto& e : es)
            namesz += static_cast<DWORD>(sizeof(WORD) + e.name.size() + 1);
    }
    DWORD total = descsz + iatsz + namesz;

    auto emit = [&](BYTE* data, DWORD nrva) {
        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(data);
        DWORD ip = descsz, np = descsz + iatsz, di = 0;
        for (const auto& [m, es] : bymod) {
            IMAGE_IMPORT_DESCRIPTOR d{};
            d.Name = nrva + np;
            d.FirstThunk = nrva + ip;
            d.OriginalFirstThunk = nrva + ip + static_cast<DWORD>((es.size() + 1) * sizeof(uint64_t));
            desc[di] = d;
            memcpy(data + np, m.c_str(), m.size() + 1);
            np += static_cast<DWORD>(m.size()) + 1;

            auto* iat = reinterpret_cast<uint64_t*>(data + ip);
            ip += static_cast<DWORD>((es.size() + 1) * sizeof(uint64_t) * 2);
            auto* lkt = iat + es.size() + 1;

            for (size_t i = 0; i < es.size(); i++) {
                WORD hint = 0;
                lkt[i] = static_cast<uint64_t>(nrva) + np;
                memcpy(data + np, &hint, sizeof(hint));
                memcpy(data + np + sizeof(hint), es[i].name.c_str(), es[i].name.size() + 1);
                iat[i] = lkt[i];
                np += static_cast<DWORD>(sizeof(hint) + es[i].name.size() + 1);
            }
            iat[es.size()] = 0;
            lkt[es.size()] = 0;
            di++;
        }
        ZeroMemory(&desc[di], sizeof(IMAGE_IMPORT_DESCRIPTOR));
    };

    DWORD irva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    auto place = [&](DWORD tv) -> bool { // todo: fix
        if (!tv) return false;
        auto* s = IMAGE_FIRST_SECTION(nt);
        for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (tv < s[i].VirtualAddress || tv >= s[i].VirtualAddress + s[i].Misc.VirtualSize)
                continue;

            DWORD iraw = s[i].PointerToRawData + (tv - s[i].VirtualAddress);
            DWORD av = s[i].Misc.VirtualSize - (tv - s[i].VirtualAddress);
            if (s[i].SizeOfRawData) av = std::min(av, s[i].SizeOfRawData - (tv - s[i].VirtualAddress));
            if (iraw >= b.size() || av < total || static_cast<size_t>(iraw) + total > b.size())
                return false;

            emit(b.data() + iraw, tv);
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = tv;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descsz;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = tv + descsz;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = iatsz;
            con::ok("import directory rebuilt in place at rva 0x" + std::to_string(tv) +
                    " (" + std::to_string(total) + " bytes)");
            return true;
        }
        return false;
    };

    if (place(live_irva) || place(irva)) return true;

    total = util::alignup(descsz + iatsz + namesz, fa);
    auto* s = IMAGE_FIRST_SECTION(nt);
    auto* last = &s[nt->FileHeader.NumberOfSections - 1];
    DWORD nraw = util::alignup(last->PointerToRawData + last->SizeOfRawData, fa);
    DWORD nrva = util::alignup(last->VirtualAddress + last->Misc.VirtualSize, sa);
    DWORD nend = nrva + total;

    if (nraw + total > b.size()) b.resize(static_cast<size_t>(nraw) + total, 0);

    nt = pe::nt(b);
    s = IMAGE_FIRST_SECTION(nt);
    last = &s[nt->FileHeader.NumberOfSections - 1];

    last->Misc.VirtualSize = nend - last->VirtualAddress;
    last->SizeOfRawData = std::min<DWORD>(static_cast<DWORD>(b.size() - last->PointerToRawData),
                                          nraw + total - last->PointerToRawData);
    last->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    nt->OptionalHeader.SizeOfImage = util::alignup(nend, sa);

    emit(b.data() + nraw, nrva);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = nrva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descsz;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = nrva + descsz;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = iatsz;
    con::ok("import directory appended to last section at rva 0x" + std::to_string(nrva) +
            " no new section was added\n");
    return true;
}

}  // namespace imp

namespace hyp {

constexpr DWORD pagesz = 0x1000;

bool iscode(HANDLE h, const BYTE* base, pe::sec& s) {
    if (s.hdr.Characteristics & IMAGE_SCN_CNT_CODE) { s.code = true; return true; }
    if (!s.vsize) return false;

    const BYTE* a = base + s.rva;
    const SIZE_T step = 0x100000, max = std::min<SIZE_T>(s.vsize, 16 * step);
    for (SIZE_T off = 0; off < max; off += step)
        if (mem::exec(h, a + off)) { s.code = true; return true; }
    return false;
}

struct dead {
    DWORD raw;
    SIZE_T off;
};

struct stats {
    SIZE_T patched = 0, total = 0, code = 0, data = 0, flushed = 0, deadcnt = 0;
    std::vector<dead> dead_list;
};

void dumpcode(HANDLE h, const BYTE* base, pe::sec& s, float limit, ntflush_t flush,
              std::vector<BYTE>& b, stats& st, std::vector<SIZE_T>& outdead) {
    SIZE_T n = std::min<SIZE_T>(s.vsize, b.size() - s.raw);
    SIZE_T pages = (n + pagesz - 1) / pagesz;
    SIZE_T target = static_cast<SIZE_T>(pages * limit + 0.5f);
    if (limit > 0 && !target) target = 1;
    SIZE_T to = std::min<SIZE_T>(n, target * pagesz);

    const SIZE_T wide = 8 * 1024 * 1024;
    if (flush)
        for (SIZE_T off = 0; off < to; off += wide)
            flush(h, const_cast<BYTE*>(base + s.rva + off), std::min<SIZE_T>(wide, to - off));

    SIZE_T got = 0, fl = 0;
    std::vector<SIZE_T> deadmap;
    SIZE_T totalPages = pages;
    SIZE_T curPage = 0;

    printf("  decrypting %zu pages...\n", totalPages);
    auto pump = [&](const BYTE* a, SIZE_T len) {
        if (flush) { flush(h, const_cast<BYTE*>(a), len); fl++; }
    };

    for (SIZE_T off = 0; off < to; off += pagesz) {
        const BYTE* a = base + s.rva + off;
        SIZE_T len = std::min<SIZE_T>(pagesz, n - off);
        pump(a, len);

        SIZE_T r = mem::page(h, a, len, b.data() + s.raw + off);
        got += r;
        if (!r) deadmap.push_back(off);

        curPage++;
        if (curPage % 256 == 0 || curPage == totalPages)
            printf("  progress: %zu / %zu pages (%zu%%)\n",
                   curPage, totalPages, curPage * 100 / totalPages);
    }

    st.flushed += fl;
    st.patched += got;
    st.total += n;
    st.code++;

    s.hdr.Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    s.hdr.Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
    printf("    code section done: %zu / %zu bytes (%zu flushed, %zu forced)\n",
           got, n, fl, deadmap.size());
}

void dumpdata(HANDLE h, const BYTE* base, pe::sec& s, ntflush_t flush,
              std::vector<BYTE>& b, stats& st) {
    if (!s.raw || !s.rawsz || s.raw >= b.size()) return;

    SIZE_T vs = s.vsize ? s.vsize : s.rawsz;
    SIZE_T n = std::min<SIZE_T>(s.rawsz, vs);
    if (n > b.size() - s.raw) n = b.size() - s.raw;

    SIZE_T got = 0, fl = 0;
    SIZE_T totalPages = (n + pagesz - 1) / pagesz;
    SIZE_T curPage = 0;

    printf("  decrypting %zu pages...\n", totalPages);
    auto pump = [&](const BYTE* a, SIZE_T len) {
        if (!mem::readable(h, a) && flush) { flush(h, const_cast<BYTE*>(a), len); fl++; }
    };

    for (SIZE_T off = 0; off < n; off += pagesz) {
        const BYTE* a = base + s.rva + off;
        SIZE_T len = std::min<SIZE_T>(pagesz, n - off);
        pump(a, len);
        got += mem::page(h, a, len, b.data() + s.raw + off);

        curPage++;
        if (curPage % 256 == 0 || curPage == totalPages)
            printf("  progress: %zu / %zu pages (%zu%%)\n",
                   curPage, totalPages, curPage * 100 / totalPages);
    }

    st.flushed += fl;
    st.patched += got;
    st.data++;
    printf("    data section done: %zu / %zu bytes\n", got, n);
}

float limit(int argc, char** argv) {
    if (argc < 2) return 1.0f;
    float p = static_cast<float>(atof(argv[1]));
    return (p > 0.0f && p <= 100.0f) ? p / 100.0f : 1.0f;
}

inline uint32_t cl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

void cq(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = cl(d, 16);
    c += d; b ^= c; b = cl(b, 12);
    a += b; d ^= a; d = cl(d, 8);
    c += d; b ^= c; b = cl(b, 7);
}

void cblock(const uint8_t key[32], uint32_t ctr, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; i++)
        x[4 + i] = uint32_t(key[4 * i]) | (uint32_t(key[4 * i + 1]) << 8) |
                   (uint32_t(key[4 * i + 2]) << 16) | (uint32_t(key[4 * i + 3]) << 24);
    x[12] = ctr;
    for (int i = 0; i < 3; i++)
        x[13 + i] = uint32_t(nonce[4 * i]) | (uint32_t(nonce[4 * i + 1]) << 8) |
                    (uint32_t(nonce[4 * i + 2]) << 16) | (uint32_t(nonce[4 * i + 3]) << 24);
    uint32_t y[16];
    memcpy(y, x, sizeof(x));

    for (int i = 0; i < 10; i++) {
        cq(x[0], x[4], x[8], x[12]);   cq(x[1], x[5], x[9], x[13]);
        cq(x[2], x[6], x[10], x[14]);  cq(x[3], x[7], x[11], x[15]);
        cq(x[0], x[5], x[10], x[15]);  cq(x[1], x[6], x[11], x[12]);
        cq(x[2], x[7], x[8], x[13]);   cq(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        x[i] += y[i];
        memcpy(out + 4 * i, &x[i], 4);
    }
}

void cstream(const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr, uint8_t* out,
             size_t n) {
    uint8_t blk[64];
    for (size_t i = 0; i < n; i += 64) {
        cblock(key, ctr + static_cast<uint32_t>(i / 64), nonce, blk);
        memcpy(out + i, blk, std::min<size_t>(64, n - i));
    }
}

bool cscan(const uint8_t* p, size_t n, const uint8_t nonce[12], uint32_t ctr,
           const uint8_t want[64], uint8_t* key) {
    uint8_t out[64];
    for (size_t o = 0; o + 32 <= n; o += 8) {
        cblock(p + o, ctr, nonce, out);
        if (!memcmp(out, want, 64)) {
            memcpy(key, p + o, 32);
            return true;
        }
    }
    return false;
}

bool grabscan(HANDLE h, const BYTE* a, size_t len, const uint8_t nonce[12], uint32_t ctr,
              const uint8_t want[64], uint8_t* key) {
    const size_t chunk = 1u << 20;
    std::vector<BYTE> buf(chunk);
    for (size_t o = 0; o < len;) {
        size_t n = std::min(chunk, len - o);
        SIZE_T rd = 0;
        if (ReadProcessMemory(h, a + o, buf.data(), static_cast<SIZE_T>(n), &rd) && rd &&
            cscan(buf.data(), rd, nonce, ctr, want, key)) {
            return true;
        }
        o += rd ? rd : 0x1000;
    }
    return false;
}

std::string hex32(const uint8_t k[32]) {
    std::string s;
    for (int i = 0; i < 32; i++) {
        char t[4];
        snprintf(t, 4, "%02X", k[i]);
        s += t;
    }
    return s;
}

}  // namespace hyp

bool save(const std::string& p, const std::vector<BYTE>& b) {
    std::ofstream out(p, std::ios::binary);
    out.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    return out.good();
}

int main(int argc, char* argv[]) {
    util::vt();

    const float lim = hyp::limit(argc, argv);
    printf("made by kellan\n @kellanvisor on discord\n");
    con::info("decryption limit: %.0f%%\n", lim * 100.0f);

    DWORD pid = proc::find(L"RobloxPlayerBeta.exe");
    if (!pid) { con::fail("roblox not running"); return 1; }

util::handle ph(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION |
                                PROCESS_CREATE_THREAD,
                            FALSE, pid));
    if (!ph) { con::fail("openprocess failed"); return 1; }
    HANDLE h = ph.get();

    PVOID base = nullptr;
    DWORD msz = 0;
    if (!proc::mod(h, L"RobloxPlayerBeta.exe", &base, &msz)) { con::fail("module not found"); return 1; }

    const std::string disk = proc::path(pid);
    con::info("robloxplayerbeta.exe @ 0x%p  %u bytes\n", base, static_cast<unsigned>(msz));
    printf("disk: %s\n", disk.c_str());

    std::vector<BYTE> b = pe::load(disk);
    if (b.empty()) { con::fail("cannot read disk image"); return 1; }
    con::ok("loaded " + std::to_string(b.size()) + " bytes from disk");
    const std::vector<BYTE> rawimg = b;

    std::vector<pe::sec> sect = pe::secs(b);
    if (sect.empty()) { con::fail("no sections found"); return 1; }

    const BYTE* rb = static_cast<const BYTE*>(base);
    auto flush = reinterpret_cast<ntflush_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                            "NtFlushInstructionCache"));
    hyp::stats st;

    for (auto& s : sect) {
        if (!s.vsize || s.raw >= b.size()) continue;

        if (hyp::iscode(h, rb, s)) {
            printf("code section%s: rva=0x%X vsize=0x%X\n",
                   (s.hdr.Characteristics & IMAGE_SCN_CNT_CODE) ? "" : " (exec in mem)",
                   static_cast<unsigned>(s.rva), static_cast<unsigned>(s.vsize));
            printf("  decrypting code section @ rva 0x%X\n", static_cast<unsigned>(s.rva));
            std::vector<SIZE_T> deads;
            hyp::dumpcode(h, rb, s, lim, flush, b, st, deads);
            for (SIZE_T off : deads) st.dead_list.push_back({ s.raw, off });
        } else {
            printf("data section: rva=0x%X vsize=0x%X\n",
                   static_cast<unsigned>(s.rva), static_cast<unsigned>(s.vsize));
            printf("  decrypting data section @ rva 0x%X\n", static_cast<unsigned>(s.rva));
            hyp::dumpdata(h, rb, s, flush, b, st);
        }
    }

    pe::commit(b, sect);
    pe::fixsiz(b);
    pe::runnable(b, rb);
    con::info("imagebase fixed to 0x%p\n", base);

    con::ok("patched " + std::to_string(st.patched) + " / " + std::to_string(st.total) +
            " bytes across " + std::to_string(st.code) + " code sections, dead ( undecryptable ) pages: " +
            std::to_string(st.deadcnt) + ")");

    con::info("building export map...\n");
    auto ex = imp::exportmap(h);
    printf("  %zu exports\n", ex.size());

    con::info("scanning for imports...\n");
    auto imports = imp::find(b, ex);
    printf("  %zu imports found\n", imports.size());

    DWORD live_irva = 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nh;
    if (mem::read(h, rb, &dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        mem::read(h, rb + dos.e_lfanew, &nh) && nh.Signature == IMAGE_NT_SIGNATURE)
        live_irva = nh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (live_irva)
        con::info("live import dir at rva 0x%X\n", static_cast<unsigned>(live_irva));

    imp::rebuild(b, imports, live_irva);

    con::info("saving dumped.exe...\n");
    if (!save("dumped.exe", b)) { con::fail("failed to write dumped.exe"); return 1; }
    con::ok("saved dumped.exe (" + std::to_string(b.size()) + " bytes)");
    return 0;
}
