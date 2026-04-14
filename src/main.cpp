#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <thread>
#include <iomanip>

// ---------------------------------------------------------------------------
// Console Utilities
// ---------------------------------------------------------------------------
enum class Color { Default, Red, Green, Yellow, Cyan };
void SetColor(Color c) {
    static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (c) {
        case Color::Red:    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY); break;
        case Color::Green:  SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::Yellow: SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case Color::Cyan:   SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        default:            SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }
}

void PrintStatus(const std::string& msg, Color c = Color::Default) {
    SetColor(c);
    std::cout << "[*] " << msg << "\n";
    SetColor(Color::Default);
}

// ---------------------------------------------------------------------------
// NT Functions (Loaded dynamically)
// ---------------------------------------------------------------------------
using pNtSuspendProcess = NTSTATUS(NTAPI*)(HANDLE);
using pNtResumeProcess  = NTSTATUS(NTAPI*)(HANDLE);
static pNtSuspendProcess NtSuspendProcess = nullptr;
static pNtResumeProcess  NtResumeProcess  = nullptr;

bool LoadNTFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    NtSuspendProcess = reinterpret_cast<pNtSuspendProcess>(GetProcAddress(ntdll, "NtSuspendProcess"));
    NtResumeProcess  = reinterpret_cast<pNtResumeProcess>(GetProcAddress(ntdll, "NtResumeProcess"));
    return NtSuspendProcess && NtResumeProcess;
}

// ---------------------------------------------------------------------------
// Process Finder
// ---------------------------------------------------------------------------
DWORD FindProcessId(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                CloseHandle(snap); return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap); return 0;
}

// ---------------------------------------------------------------------------
// Manual Mapper
// ---------------------------------------------------------------------------
class ManualMapper {
public:
    static bool Map(HANDLE hProcess, const std::filesystem::path& dllPath, HANDLE hSyncEvent) {
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;
        size_t size = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buf(size);
        file.read(reinterpret_cast<char*>(buf.data()), size);

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buf.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        size_t imgSize = nt->OptionalHeader.SizeOfImage;
        void* remoteBase = VirtualAllocEx(hProcess, nullptr, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) return false;

        WriteProcessMemory(hProcess, remoteBase, buf.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                buf.data() + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
            WriteProcessMemory(hProcess,
                reinterpret_cast<BYTE*>(remoteBase) + sec->VirtualAddress,
                buf.data() + sec->PointerToRawData,
                sec->SizeOfRawData, nullptr);
        }

        uintptr_t baseAddr = reinterpret_cast<uintptr_t>(remoteBase);
        uintptr_t prefBase = nt->OptionalHeader.ImageBase;

        // Resolve Imports
        auto* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir->Size) {
            auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(baseAddr + impDir->VirtualAddress);
            for (; imp->Name; ++imp) {
                char lib[MAX_PATH]{};
                ReadProcessMemory(hProcess, reinterpret_cast<void*>(baseAddr + imp->Name), lib, MAX_PATH, nullptr);
                HMODULE hMod = LoadLibraryA(lib);
                if (!hMod) continue;
                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(baseAddr + imp->FirstThunk);
                for (; thunk->u1.Function; ++thunk) {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddr + thunk->u1.AddressOfData);
                    FARPROC addr = GetProcAddress(hMod, reinterpret_cast<char*>(ibn->Name));
                    if (addr) WriteProcessMemory(hProcess, &thunk->u1.Function, &addr, sizeof(addr), nullptr);
                }
            }
        }

        // Apply Relocations
        if (baseAddr != prefBase) {
            auto* relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relDir->Size) {
                auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseAddr + relDir->VirtualAddress);
                auto* end = reinterpret_cast<BYTE*>(rel) + relDir->Size;
                while (reinterpret_cast<BYTE*>(rel) < end && rel->SizeOfBlock) {
                    uint32_t count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    auto* entries = reinterpret_cast<WORD*>(rel + 1);
                    for (uint32_t i = 0; i < count; ++i) {
                        uint32_t type = entries[i] >> 12;
                        uint32_t off = entries[i] & 0xFFF;
                        if (type == IMAGE_REL_BASED_HIGHLOW) {
                            uintptr_t* addr = reinterpret_cast<uintptr_t*>(baseAddr + rel->VirtualAddress + off);
                            uint32_t delta = static_cast<uint32_t>(baseAddr - prefBase);
                            uint32_t val;
                            ReadProcessMemory(hProcess, addr, &val, sizeof(val), nullptr);
                            val += delta;
                            WriteProcessMemory(hProcess, addr, &val, sizeof(val), nullptr);
                        }
                    }
                    rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(rel) + rel->SizeOfBlock);
                }
            }
        }

        // Call DllMain
        uintptr_t entry = baseAddr + nt->OptionalHeader.AddressOfEntryPoint;
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(entry),
            hSyncEvent, 0, nullptr);
        if (!hThread) return false;
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return true;
    }
};

// ---------------------------------------------------------------------------
// TUI Main
// ---------------------------------------------------------------------------
int main() {
    SetConsoleOutputCP(CP_UTF8);
    if (!LoadNTFunctions()) {
        PrintStatus("Failed to load NTAPI functions.", Color::Red);
        return 1;
    }

    PrintStatus("CS2 TUI Manual Mapper Injector v1.0", Color::Cyan);
    std::cout << std::string(40, '-') << "\n";

    std::wstring procName;
    std::filesystem::path dllPath;

    // 1. Input Validation Loop
    while (procName.empty()) {
        std::cout << "[?] Enter target process name (e.g., cs2.exe): ";
        std::getline(std::wcin, procName);
        if (procName.empty()) PrintStatus("Input cannot be empty.", Color::Yellow);
    }

    while (!std::filesystem::exists(dllPath)) {
        std::cout << "[?] Enter DLL path (drag & drop supported): ";
        std::wstring input; std::getline(std::wcin, input);
        if (input.front() == L'"' && input.back() == L'"') input = input.substr(1, input.size() - 2);
        dllPath = input;
        if (!std::filesystem::exists(dllPath)) PrintStatus("DLL not found. Check path.", Color::Yellow);
    }

    PrintStatus("Searching for process...", Color::Default);
    DWORD pid = FindProcessId(procName);
    if (!pid) {
        PrintStatus("Process not found. Ensure it's running.", Color::Red);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        PrintStatus("Failed to open process. Run as Administrator.", Color::Red);
        return 1;
    }

    // 2. Freeze Process
    PrintStatus("Freezing target process...", Color::Yellow);
    if (NtSuspendProcess(hProcess) != 0) {
        PrintStatus("Failed to suspend process.", Color::Red);
        CloseHandle(hProcess); return 1;
    }

    // 3. Sync Event
    HANDLE hReady = CreateEventA(nullptr, TRUE, FALSE, "CS2_DLL_INIT_DONE");
    if (!hReady) {
        PrintStatus("Failed to create sync event.", Color::Red);
        NtResumeProcess(hProcess); CloseHandle(hProcess); return 1;
    }

    // 4. Manual Map
    PrintStatus("Allocating & mapping DLL...", Color::Cyan);
    bool mapped = ManualMapper::Map(hProcess, dllPath, hReady);
    if (!mapped) {
        PrintStatus("DLL mapping failed. Check architecture (x64) & PE validity.", Color::Red);
        CloseHandle(hReady); NtResumeProcess(hProcess); CloseHandle(hProcess); return 1;
    }

    // 5. Wait for DLL Initialization
    PrintStatus("Waiting for DLL initialization (timeout: 30s)...", Color::Yellow);
    DWORD wait = WaitForSingleObject(hReady, 30000);
    if (wait == WAIT_OBJECT_0) {
        PrintStatus("DLL signaled ready. Hooks installed.", Color::Green);
    } else if (wait == WAIT_TIMEOUT) {
        PrintStatus("Timeout. DLL may not be signaling the event.", Color::Yellow);
    } else {
        PrintStatus("Unexpected wait error.", Color::Red);
    }

    // 6. Unfreeze & Cleanup
    PrintStatus("Resuming target process...", Color::Green);
    NtResumeProcess(hProcess);
    CloseHandle(hReady);
    CloseHandle(hProcess);

    PrintStatus("Injection complete. Press any key to exit.", Color::Cyan);
    std::cin.get();
    return 0;
}
