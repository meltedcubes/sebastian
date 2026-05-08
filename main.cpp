#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <unordered_map>
#include <set>
#include <cstdint>
#include <map>
#pragma comment(lib, "ntdll.lib")

using NtFlushInstructionCache_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, SIZE_T);

namespace con {
    constexpr auto R = "\033[31m";
    constexpr auto G = "\033[32m";
    constexpr auto Y = "\033[33m";
    constexpr auto C = "\033[36m";
    constexpr auto B = "\033[1m";
    constexpr auto X = "\033[0m";

    template<typename... Args>
    void info(const char* fmt, Args... args) {
        printf("%s%s[ info ]%s ", B, C, X);
        printf(fmt, args...);
    }
    void ok(const char* msg)    { printf("%s%s[ success ]%s %s\n", B, G, X, msg); }
    void fail(const char* msg)  { printf("%s%s[ fail ]%s %s\n", B, R, X, msg); }
    void warn(const char* msg)  { printf("%s%s[ warn ]%s %s\n", B, Y, X, msg); }
}

namespace proc {
    DWORD find(const wchar_t* name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do { if (!_wcsicmp(pe.szExeFile, name)) { CloseHandle(snap); return pe.th32ProcessID; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap); return 0;
    }

    bool get_module(HANDLE h, const wchar_t* name, PVOID* base, DWORD* size) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(h));
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(snap, &me)) {
            do { if (!_wcsicmp(me.szModule, name)) {
                *base = me.modBaseAddr; *size = me.modBaseSize;
                CloseHandle(snap); return true;
            } } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap); return false;
    }

    std::vector<MODULEENTRY32W> get_all_modules(HANDLE h) {
        std::vector<MODULEENTRY32W> result;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(h));
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(snap, &me)) {
            do { result.push_back(me);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return result;
    }

    std::wstring path(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return L"";
        WCHAR buf[MAX_PATH]; DWORD len = MAX_PATH;
        BOOL ok = QueryFullProcessImageNameW(h, 0, buf, &len);
        CloseHandle(h);
        return ok ? std::wstring(buf) : L"";
    }
}

namespace mem {
    bool readable(HANDLE h, PVOID addr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(h, addr, &mbi, sizeof(mbi))) return false;
        return mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0;
    }

    SIZE_T read_page(HANDLE h, PVOID addr, SIZE_T max, BYTE* out) {
        SIZE_T read = 0;
        ReadProcessMemory(h, addr, out, max, &read);
        return read;
    }

    template<typename T>
    bool read(HANDLE h, PVOID addr, T* out) {
        SIZE_T r;
        return ReadProcessMemory(h, addr, out, sizeof(T), &r) && r == sizeof(T);
    }
}

namespace pe {
    struct Section {
        DWORD rva;
        DWORD vsize;
        DWORD raw;
    };

    std::vector<Section> get_code_sections(const std::vector<BYTE>& buf) {
        std::vector<Section> result;
        auto* dos = (PIMAGE_DOS_HEADER)buf.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;
        auto* nt = (PIMAGE_NT_HEADERS)(buf.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return result;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                result.push_back({ sec[i].VirtualAddress, sec[i].Misc.VirtualSize, sec[i].PointerToRawData });
            }
        }
        return result;
    }

    PIMAGE_NT_HEADERS get_nt_headers(std::vector<BYTE>& buf) {
        auto* dos = (PIMAGE_DOS_HEADER)buf.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        return (PIMAGE_NT_HEADERS)(buf.data() + dos->e_lfanew);
    }

    DWORD rva_to_offset(std::vector<BYTE>& buf, DWORD rva) {
        auto* nt = get_nt_headers(buf);
        if (!nt) return 0;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
            }
        }
        return 0;
    }
}

namespace imports {
    struct ImportEntry {
        std::string module;
        std::string name;
        uint64_t    iat_rva;
        uint64_t    address;
    };

    std::unordered_map<uint64_t, std::pair<std::string, std::string>> build_export_map(HANDLE h, PVOID target_base) {
        std::unordered_map<uint64_t, std::pair<std::string, std::string>> map;
        auto modules = proc::get_all_modules(h);

        for (auto& mod : modules) {
            IMAGE_DOS_HEADER dos;
            IMAGE_NT_HEADERS nt;
            if (!mem::read(h, mod.modBaseAddr, &dos)) continue;
            if (!mem::read(h, (BYTE*)mod.modBaseAddr + dos.e_lfanew, &nt)) continue;
            if (nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) continue;

            DWORD export_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD export_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            std::vector<BYTE> export_data(export_size);
            ReadProcessMemory(h, (BYTE*)mod.modBaseAddr + export_rva, export_data.data(), export_size, nullptr);

            auto* exp_dir = (PIMAGE_EXPORT_DIRECTORY)export_data.data();
            if (!exp_dir->NumberOfFunctions) continue;

            auto* names = (DWORD*)(export_data.data() + exp_dir->AddressOfNames - export_rva);
            auto* funcs = (DWORD*)(export_data.data() + exp_dir->AddressOfFunctions - export_rva);
            auto* ords  = (WORD*)(export_data.data() + exp_dir->AddressOfNameOrdinals - export_rva);

            char mb_name[256];
            WideCharToMultiByte(CP_UTF8, 0, mod.szModule, -1, mb_name, sizeof(mb_name), nullptr, nullptr);
            std::string module_name(mb_name);

            for (DWORD i = 0; i < exp_dir->NumberOfNames; i++) {
                if (ords[i] >= exp_dir->NumberOfFunctions) continue;
                char* name = (char*)(export_data.data() + names[i] - export_rva);
                DWORD func_rva = funcs[ords[i]];
                uint64_t func_addr = (uint64_t)mod.modBaseAddr + func_rva;
                map[func_addr] = { module_name, std::string(name) };
            }
        }
        return map;
    }

    std::vector<ImportEntry> find_imports(
        HANDLE h, PVOID base, std::vector<BYTE>& buf,
        std::unordered_map<uint64_t, std::pair<std::string, std::string>>& exports)
    {
        std::vector<ImportEntry> result;
        std::set<uint64_t> seen;

        auto* nt = pe::get_nt_headers(buf);
        if (!nt) return result;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;

            DWORD off = sec[i].PointerToRawData;
            DWORD end = off + ((sec[i].SizeOfRawData < sec[i].Misc.VirtualSize)
                ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize);
            if (end > buf.size()) end = buf.size();

            for (DWORD pos = off; pos + 8 <= end; pos += 8) {
                uint64_t val = *(uint64_t*)(buf.data() + pos);
                auto it = exports.find(val);
                if (it != exports.end() && !seen.count(val)) {
                    ImportEntry entry;
                    entry.module  = it->second.first;
                    entry.name    = it->second.second;
                    entry.address = val;
                    entry.iat_rva = pe::rva_to_offset(buf, pos);
                    result.push_back(entry);
                    seen.insert(val);
                }
            }
        }
        return result;
    }

  void rebuild_imports(std::vector<BYTE>& buf, const std::vector<ImportEntry>& imports) {
    if (imports.empty()) {
        printf("  no imports to rebuild\n");
        return;
    }

    printf("  rebuilding %zu imports...\n", imports.size());
    fflush(stdout);

    // group by module
    std::map<std::string, std::vector<ImportEntry>> by_module;
    for (auto& imp : imports) by_module[imp.module].push_back(imp);

    auto* nt = pe::get_nt_headers(buf);
    if (!nt) return;

    DWORD file_align = nt->OptionalHeader.FileAlignment ? nt->OptionalHeader.FileAlignment : 0x200;
    DWORD sect_align = nt->OptionalHeader.SectionAlignment ? nt->OptionalHeader.SectionAlignment : 0x1000;

    // calculate sizes
    DWORD desc_count = by_module.size() + 1;
    DWORD desc_size  = desc_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    DWORD iat_size = 0, name_size = 0;
    for (auto& [mod, entries] : by_module) {
        iat_size  += (entries.size() + 1) * sizeof(uint64_t) * 2;
        name_size += mod.length() + 1;
        for (auto& e : entries) {
            name_size += sizeof(WORD) + e.name.length() + 1;
        }
    }

    DWORD total_size = desc_size + iat_size + name_size;
    total_size = ((total_size + file_align - 1) / file_align) * file_align;

    printf("  desc=%d iat=%d names=%d total=%d\n", desc_size, iat_size, name_size, total_size);
    fflush(stdout);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    auto* last = &sec[nt->FileHeader.NumberOfSections - 1];
    DWORD new_raw = ((last->PointerToRawData + last->SizeOfRawData + file_align - 1) / file_align) * file_align;
    DWORD new_rva = ((last->VirtualAddress + last->Misc.VirtualSize + sect_align - 1) / sect_align) * sect_align;

    printf("  new_raw=0x%X new_rva=0x%X\n", new_raw, new_rva);
    fflush(stdout);

    auto* new_sec = &sec[nt->FileHeader.NumberOfSections];
    memset(new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(new_sec->Name, ".hetalia", 8);
    new_sec->VirtualAddress   = new_rva;
    new_sec->Misc.VirtualSize = ((total_size + sect_align - 1) / sect_align) * sect_align;
    new_sec->PointerToRawData = new_raw;
    new_sec->SizeOfRawData    = total_size;
    new_sec->Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = new_sec->VirtualAddress + new_sec->Misc.VirtualSize;

    size_t old_size = buf.size();
    buf.resize(new_raw + total_size, 0);
        buf.resize(new_raw + total_size, 0);
        nt = pe::get_nt_headers(buf);
        sec = IMAGE_FIRST_SECTION(nt);
        last = &sec[nt->FileHeader.NumberOfSections - 1];

        printf("  buffer: %zu -> %zu\n", old_size, buf.size());
        fflush(stdout);

    BYTE* data = buf.data() + new_raw;
    DWORD iat_pos  = desc_size;
    DWORD name_pos = desc_size + iat_size;
    auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)data;
    int di = 0;

    for (auto& [mod, entries] : by_module) {
        printf("  module: %s (%zu imports)\n", mod.c_str(), entries.size());
        fflush(stdout);

        // write module name
        if (name_pos + mod.length() + 1 > total_size) {
            printf("  overflow at module name\n");
            fflush(stdout);
            return;
        }
        memcpy(data + name_pos, mod.c_str(), mod.length() + 1);
        desc[di].Name = new_rva + name_pos;
        name_pos += mod.length() + 1;

        // IAT
        desc[di].FirstThunk = new_rva + iat_pos;
        auto* iat = (uint64_t*)(data + iat_pos);
        iat_pos += (entries.size() + 1) * sizeof(uint64_t);

        // lookup table
        desc[di].OriginalFirstThunk = new_rva + iat_pos;
        auto* lkt = (uint64_t*)(data + iat_pos);

        for (size_t ei = 0; ei < entries.size(); ei++) {
            if (name_pos + sizeof(WORD) + entries[ei].name.length() + 1 > total_size) {
                printf("  overflow at entry %zu\n", ei);
                fflush(stdout);
                return;
            }
            WORD hint = 0;
            memcpy(data + name_pos, &hint, sizeof(WORD));
            memcpy(data + name_pos + 2, entries[ei].name.c_str(), entries[ei].name.length() + 1);

            iat[ei] = entries[ei].address;
            lkt[ei] = new_rva + name_pos;
            name_pos += sizeof(WORD) + entries[ei].name.length() + 1;
        }

        iat[entries.size()] = 0;
        lkt[entries.size()] = 0;
        iat_pos += (entries.size() + 1) * sizeof(uint64_t);
        di++;
    }

    memset(&desc[di], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_rva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = desc_size;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = new_rva + desc_size;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = iat_size;

    printf("  done\n");
    fflush(stdout);
}
}

int main(int argc, char* argv[]) {
    float limit = 1.0f;
    if (argc >= 2) {
        limit = (float)atof(argv[1]) / 100.0f;
        if (limit <= 0.0f || limit > 1.0f) limit = 1.0f;
    }
    printf("Made by lucef\n @6sjt on discord\n");
    con::info("decryption limit: %.0f%%\n", limit * 100.0f);

    DWORD pid = proc::find(L"RobloxPlayerBeta.exe");
    if (!pid) { con::fail("roblox not running"); return 1; }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!h) { con::fail("OpenProcess failed"); return 1; }

    auto NtFlush = (NtFlushInstructionCache_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFlushInstructionCache");

    PVOID base; DWORD module_size;
    if (!proc::get_module(h, L"RobloxPlayerBeta.exe", &base, &module_size)) {
        con::fail("module not found"); CloseHandle(h); return 1;
    }

    auto disk_path = proc::path(pid);
    con::info("RobloxPlayerBeta.exe @ 0x%p  %d bytes\n", base, module_size);
    wprintf(L"disk: %s\n", disk_path.c_str());

    std::vector<BYTE> buf;
    HANDLE fh = CreateFileW(disk_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) { con::fail("cannot open disk file"); CloseHandle(h); return 1; }

    DWORD file_size = GetFileSize(fh, nullptr);
    buf.resize(file_size);
    DWORD rd;
    ReadFile(fh, buf.data(), file_size, &rd, nullptr);
    CloseHandle(fh);
    buf.resize(rd);
    con::ok(("loaded " + std::to_string(rd) + " bytes from disk").c_str());

    auto sections = pe::get_code_sections(buf);
    if (sections.empty()) { con::fail("no executable sections"); CloseHandle(h); return 1; }
    printf("code sections: %zu\n", sections.size());

    SIZE_T total_patched = 0, total_code = 0;

    for (const auto& sec : sections) {
        if (sec.vsize == 0 || sec.raw >= buf.size()) continue;

        SIZE_T max_readable = ((SIZE_T)sec.vsize < (SIZE_T)(buf.size() - sec.raw))
            ? (SIZE_T)sec.vsize : (SIZE_T)(buf.size() - sec.raw);

        printf("  rva 0x%X  raw 0x%X  size %d  max %zu\n", sec.rva, sec.raw, sec.vsize, max_readable);

        SIZE_T section_patched = 0, flushed = 0, already_readable = 0, skipped = 0;
        SIZE_T total_pages = max_readable / 0x1000;
        SIZE_T target_pages = (SIZE_T)(total_pages * limit);

        for (SIZE_T off = 0; off < max_readable; off += 0x1000) {
            SIZE_T current_page = off / 0x1000;

            if (current_page >= target_pages) {
                skipped = total_pages - current_page;
                break;
            }

            auto addr = (BYTE*)base + sec.rva + off;
            SIZE_T chunk = (0x1000ull < (max_readable - off)) ? 0x1000ull : (max_readable - off);

            if (mem::readable(h, addr)) {
                section_patched += mem::read_page(h, addr, chunk, buf.data() + sec.raw + off);
                already_readable++;
            } else if (NtFlush) {
                NtFlush(h, addr, chunk);
                flushed++;
                if (mem::readable(h, addr)) {
                    section_patched += mem::read_page(h, addr, chunk, buf.data() + sec.raw + off);
                }
            }

            printf("\r    [%5zu / %5zu] %3.0f%%  read=%zu flush=%zu",
                current_page, total_pages, 100.0 * off / max_readable, already_readable, flushed);
        }

        if (skipped) {
            printf("\r    [%5zu / %5zu] %.0f%%  read=%zu flush=%zu  (skipped %zu)\n",
                target_pages, total_pages, limit * 100.0, already_readable, flushed, skipped);
        } else {
            printf("\r    [%5zu / %5zu] 100%%  read=%zu flush=%zu  done\n",
                total_pages, total_pages, already_readable, flushed);
        }

        total_patched += section_patched;
        total_code += max_readable;
    }
    con::ok(("patched " + std::to_string(total_patched) + " / " + std::to_string(total_code) + " bytes").c_str());

    // flush data sections
    con::info("flushing data sections...\n");
    auto* nt_flush = pe::get_nt_headers(buf);
    auto* sec_flush = IMAGE_FIRST_SECTION(nt_flush);
    for (int i = 0; i < nt_flush->FileHeader.NumberOfSections; i++) {
        if (sec_flush[i].Characteristics & IMAGE_SCN_CNT_CODE) continue;
        if (!sec_flush[i].PointerToRawData || !sec_flush[i].SizeOfRawData) continue;

        DWORD raw = sec_flush[i].PointerToRawData;
        DWORD size = sec_flush[i].SizeOfRawData;
        DWORD rva = sec_flush[i].VirtualAddress;
        if (size > sec_flush[i].Misc.VirtualSize) size = sec_flush[i].Misc.VirtualSize;

        char name[9] = {0};
        memcpy(name, sec_flush[i].Name, 8);
        printf("  %s: rva=0x%X size=%d\n", name, rva, size);

        SIZE_T pages = size / 0x1000;
        for (SIZE_T off = 0; off < size; off += 0x1000) {
            auto addr = (BYTE*)base + rva + off;
            SIZE_T chunk = (0x1000ull < (size - off)) ? 0x1000ull : (size - off);

            if (!mem::readable(h, addr) && NtFlush) {
                NtFlush(h, addr, chunk);
            }

            if (mem::readable(h, addr)) {
                mem::read_page(h, addr, chunk, buf.data() + raw + off);
            }

            if ((off / 0x1000) % 100 == 0) {
                printf("\r    [%3zu%%]", (off / 0x1000) * 100 / (pages ? pages : 1));
            }
        }
        printf("\r    100%% done\n");
    }

    // resolve imports
    con::info("building export map...\n");
    auto exports = imports::build_export_map(h, base);
    printf("  %zu exports\n", exports.size());

    con::info("scanning for imports...\n");
    auto found_imports = imports::find_imports(h, base, buf, exports);
    printf("  %zu imports found\n", found_imports.size());

    if (!found_imports.empty()) {
        con::info("rebuilding import directory...\n");
        imports::rebuild_imports(buf, found_imports);
        con::ok("import directory rebuilt");
    }

    // save
    con::info("saving to file...\n");
    std::ofstream out("dumped.exe", std::ios::binary);
    if (!out.is_open()) {
        con::fail("failed to open output file");
        CloseHandle(h);
        return 1;
    }
    out.write((char*)buf.data(), buf.size());
    out.close();
    con::ok(("saved dumped.exe (" + std::to_string(buf.size()) + " bytes)").c_str());

    CloseHandle(h);
    return 0;
}