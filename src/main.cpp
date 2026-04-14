#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>

#pragma comment(lib, "ntdll")

// ---------------------------------------------------------------------------
// Undocumented NT functions (loaded dynamically to avoid link issues)
// ---------------------------------------------------------------------------
using pNtSuspendProcess = NTSTATUS (NTAPI*)(HANDLE);
using pNtResumeProcess  = NTSTATUS (NTAPI*)(HANDLE);

static pNtSuspendProcess NtSuspendProcess = nullptr;
static pNtResumeProcess  NtResumeProcess  = nullptr;

bool InitNtFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    NtSuspendProcess = reinterpret_cast<pNtSuspendProcess>(GetProcAddress(ntdll, "NtSuspendProcess"));
    NtResumeProcess  = reinterpret_cast<pNtResumeProcess>(GetProcAddress(ntdll, "NtResumeProcess"));
    return NtSuspendProcess && NtResumeProcess;
}

// ---------------------------------------------------------------------------
// Utility: Find CS2 PID
// ---------------------------------------------------------------------------
DWORD GetProcessIdByName(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// ---------------------------------------------------------------------------
// Manual Mapping Core
// ---------------------------------------------------------------------------
class ManualMapper {
public:
    static bool MapDll(HANDLE hProcess, const std::filesystem::path& dllPath, HANDLE hReadyEvent) {
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;
        size_t fileSize = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);
        std::vector<BYTE> buffer(fileSize);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) return false;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        size_t imageSz = nt->OptionalHeader.SizeOfImage;
        void* remoteBase = VirtualAllocEx(hProcess, nullptr, imageSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) return false;

        // Copy headers & sections
        WriteProcessMemory(hProcess, remoteBase, buffer.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                reinterpret_cast<BYTE*>(buffer.data()) + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
            WriteProcessMemory(hProcess, 
                               reinterpret_cast<BYTE*>(remoteBase) + sec->VirtualAddress,
                               buffer.data() + sec->PointerToRawData,
                               sec->SizeOfRawData, nullptr);
        }

        uintptr_t remoteBaseAddr = reinterpret_cast<uintptr_t>(remoteBase);
        uintptr_t preferredBase  = nt->OptionalHeader.ImageBase;

        // Resolve imports
        auto* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir->Size) {
            auto* imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(remoteBaseAddr + impDir->VirtualAddress);
            for (; imports->Name; ++imports) {
                char dllName[MAX_PATH]{};
                ReadProcessMemory(hProcess, reinterpret_cast<void*>(remoteBaseAddr + imports->Name), dllName, MAX_PATH, nullptr);
                HMODULE hMod = LoadLibraryA(dllName);
                if (!hMod) continue;
                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(remoteBaseAddr + imports->FirstThunk);
                for (; thunk->u1.Function; ++thunk) {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(remoteBaseAddr + thunk->u1.AddressOfData);
                    FARPROC procAddr = GetProcAddress(hMod, reinterpret_cast<char*>(ibn->Name));
                    if (procAddr) WriteProcessMemory(hProcess, &thunk->u1.Function, &procAddr, sizeof(procAddr), nullptr);
                }
            }
        }

        // Apply relocations if base changed
        if (remoteBaseAddr != preferredBase) {
            auto* relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir->Size) {
                auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(remoteBaseAddr + relocDir->VirtualAddress);
                auto* end = reinterpret_cast<BYTE*>(reloc) + relocDir->Size;
                while (reinterpret_cast<BYTE*>(reloc) < end && reloc->SizeOfBlock) {
                    uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    auto* entries = reinterpret_cast<WORD*>(reloc + 1);
                    for (uint32_t i = 0; i < count; ++i) {
                        uint32_t type = entries[i] >> 12;
                        uint32_t offset = entries[i] & 0xFFF;
                        if (type == IMAGE_REL_BASED_HIGHLOW) {
                            uintptr_t* addr = reinterpret_cast<uintptr_t*>(remoteBaseAddr + reloc->VirtualAddress + offset);
                            uint32_t delta = static_cast<uint32_t>(remoteBaseAddr - preferredBase);
                            uint32_t val;
                            ReadProcessMemory(hProcess, addr, &val, sizeof(val), nullptr);
                            val += delta;
                            WriteProcessMemory(hProcess, addr, &val, sizeof(val), nullptr);
                        }
                    }
                    reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
                }
            }
        }

        // Execute DllMain
        uintptr_t entryPoint = remoteBaseAddr + nt->OptionalHeader.AddressOfEntryPoint;
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
                                            reinterpret_cast<LPTHREAD_START_ROUTINE>(entryPoint),
                                            hReadyEvent, 0, nullptr);
        if (!hThread) return false;
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return true;
    }
};

// ---------------------------------------------------------------------------
// Main Injection Flow
// ---------------------------------------------------------------------------
int main() {
    if (!InitNtFunctions()) {
        std::cerr << "[!] Failed to load NT functions.\n";
        return 1;
    }

    std::wcout << L"[~] Looking for cs2.exe...\n";
    DWORD pid = GetProcessIdByName(L"cs2.exe");
    if (!pid) {
        std::cerr << "[!] cs2.exe not found. Is the game running?\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process. Run as Administrator.\n";
        return 1;
    }

    // 1. Freeze process
    std::wcout << L"[~] Freezing CS2...\n";
    if (NtSuspendProcess(hProcess) != 0) {
        std::cerr << "[!] Failed to freeze process.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // 2. Create sync event
    HANDLE hReady = CreateEventA(nullptr, TRUE, FALSE, "CS2_DLL_INIT_DONE");
    if (!hReady) {
        std::cerr << "[!] Failed to create sync event.\n";
        NtResumeProcess(hProcess);
        CloseHandle(hProcess);
        return 1;
    }

    // 3. Manual map DLL
    std::filesystem::path dllPath = L"skinchanger.dll"; // Change to your path
    std::wcout << L"[~] Manually mapping DLL...\n";
    bool mapped = ManualMapper::MapDll(hProcess, dllPath, hReady);
    if (!mapped) {
        std::cerr << "[!] DLL mapping failed.\n";
        CloseHandle(hReady);
        NtResumeProcess(hProcess);
        CloseHandle(hProcess);
        return 1;
    }

    // 4. Wait for DLL to signal readiness
    std::wcout << L"[~] Waiting for DLL initialization...\n";
    DWORD wait = WaitForSingleObject(hReady, 30000); // 30s timeout
    if (wait == WAIT_TIMEOUT) {
        std::cerr << "[!] Timeout waiting for DLL initialization.\n";
    } else {
        std::wcout << L"[+] DLL signaled ready.\n";
    }

    // 5. Unfreeze process
    std::wcout << L"[~] Resuming CS2...\n";
    NtResumeProcess(hProcess);

    CloseHandle(hReady);
    CloseHandle(hProcess);
    std::wcout << L"[+] Done. CS2 is running.\n";
    return 0;
}
