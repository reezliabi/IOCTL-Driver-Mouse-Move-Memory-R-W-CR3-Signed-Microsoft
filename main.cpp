#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

//Memory Functions - Basic
#define IOCTL_READ_MEMORY 0x4994C7A2
#define IOCTL_WRITE_MEMORY 0x3CB02209
#define IOCTL_GET_PROCESS_BASE 0x58C23A3F
#define IOCTL_GET_PEB 0x3A628AFC

//Memory Functions - Advanced
#define IOCTL_READ_MEMORY_3 0xD7B734C // Optimized version
#define IOCTL_WRITE_MEMORY_3 0x18FF3818 // Optimized version
#define IOCTL_PROTECT_MEMORY 0x5274D429
#define IOCTL_ALLOCATE_MEMORY 0x787ADFBD
#define IOCTL_ALLOCATE_MEMORY_2 0xD3ED734
#define IOCTL_ALLOCATE_MEMORY_3 0x26B6AF08

//Pattern Scanning
#define IOCTL_PATTERN_SCAN 0x635474F5
#define IOCTL_PATTERN_SCAN_2 0x3908664A
#define IOCTL_PATTERN_SCAN_3 0x38F8B52D
#define IOCTL_SCAN_PHYSICAL 0xCB3F9C0

//Anti-Cheat Bypass (CR3/PFN)
#define IOCTL_GET_CR3 0x3CCDAC80 // ULTIMATE BYPASS
#define IOCTL_SET_CR3 0x3CC541EF
#define IOCTL_GET_PFN_BASE 0x537C54B4 // GetImageBaseByPFN
#define IOCTL_CR3_CONTEXT 0x5314A599

//Stealth Functions
#define IOCTL_HIDE_PROCESS 0x45FB0E3F
#define IOCTL_UNLINK_PROCESS 0x41926E27
#define IOCTL_BYPASS_PATCHGUARD 0x32F6C270
#define IOCTL_HIDE_THREAD 0x7CD1D0FA
#define IOCTL_UNLINK_THREAD 0x79E4E280

//Physical Memory
#define IOCTL_READ_PHYSICAL 0x72674033
#define IOCTL_WRITE_PHYSICAL 0x71BA6926
#define IOCTL_MAP_PHYSICAL 0x96F6918
#define IOCTL_UNMAP_PHYSICAL 0x1D909008

//Syscall Hooking
#define IOCTL_HOOK_SYSCALL 0x0F43E78F
#define IOCTL_UNHOOK_SYSCALL 0x4FACD06E
#define IOCTL_GET_SYSCALL_TABLE 0x4F60158B
#define IOCTL_RESTORE_SYSCALL 0x3CCD1359

//System Enumeration
#define IOCTL_ENUM_PROCESSES 0x3CC9089E
#define IOCTL_ENUM_MODULES 0x58C23A3F
#define IOCTL_GET_MODULE_BASE 0x635474F5
#define IOCTL_GET_SYSTEM_INFO 0x787ADFBD

//---------------------------------------------------------------------------------------------------



//---------------------------------------------------------------------------------------------------

DWORD_PTR GetModuleBase(DWORD pid, const wchar_t* moduleName) {
    MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    if (Module32First(hSnap, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, moduleName) == 0) {
                CloseHandle(hSnap);
                return (DWORD_PTR)me32.modBaseAddr;
            }
        } while (Module32Next(hSnap, &me32));
    }
    CloseHandle(hSnap);
    return 0;
}

DWORD FindProcessByName(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {  // Compare wide strings
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

typedef struct _MEMORY_REQUEST {
    ULONG ProcessId;
    PVOID Address;
    PVOID Buffer;
    SIZE_T Size;
    SIZE_T BytesRead;
    NTSTATUS Status;
} MEMORY_REQUEST, * PMEMORY_REQUEST;

typedef struct _PATTERN_SCAN_REQUEST {
    PVOID BaseAddress;
    SIZE_T Size;
    PVOID Pattern;
    PCHAR Mask;
    PVOID Result;
    ULONG Flags;
} PATTERN_SCAN_REQUEST, * PPATTERN_SCAN_REQUEST;

typedef struct _CR3_CONTEXT {
    ULONG ProcessId;
    ULONG64 OriginalCR3;
    ULONG64 TargetCR3;
    BOOLEAN IsActive;
    PVOID ProcessBase;
} CR3_CONTEXT, * PCR3_CONTEXT;

typedef struct _PFN_REQUEST {
    ULONG ProcessId;
    PVOID ProcessBase;
    ULONG64 PhysicalAddress;
    PVOID VirtualAddress;
    ULONG PageCount;
} PFN_REQUEST, * PPFN_REQUEST;

enum MouseFlags
{
    None = 0,
    LeftButtonDown = 1,
    LeftButtonUp = 2,
    RightButtonDown = 4,
    RightButtonUp = 8,
    MiddleButtonDown = 16,
    MiddleButtonUp = 32,
    XButton1Down = 64,
    XButton1Up = 128,
    XButton2Down = 256,
    XButton2Up = 512,
    MouseWheel = 1024,
    MouseHorizontalWheel = 2048
};
struct NF_MOUSE_REQUEST
{
    int x;
    int y;
    short ButtonFlags;
};

class XRCDriver {
private:
    HANDLE hDevice = INVALID_HANDLE_VALUE;

public:
    bool Initialize() {
        const char* deviceName = "\\\\.\\cla300";
        hDevice = CreateFileA(
            deviceName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Failed to open device! Error code: %lu\n", GetLastError());
            return false;
        }
        printf("[+] Driver initialized successfully: %s\n", deviceName);
        return hDevice != INVALID_HANDLE_VALUE;
    }

    void Cleanup() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool ReadMemory(ULONG processId, PVOID address, PVOID buffer, SIZE_T size) {
        MEMORY_REQUEST req = { 0 };
        req.ProcessId = processId;
        req.Address = address;
        req.Buffer = buffer;
        req.Size = size;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x4994C7A2,  // IOCTL_READ_MEMORY
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        );
    }

    bool ReadMemory3(ULONG processId, PVOID address, PVOID buffer, SIZE_T size) {
        MEMORY_REQUEST req = { 0 };
        req.ProcessId = processId;
        req.Address = address;
        req.Buffer = buffer;
        req.Size = size;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0xD7B734C,   // IOCTL_READ_MEMORY_3 (10x faster)
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        );
    }



    bool WriteMemory3(ULONG processId, PVOID address, PVOID buffer, SIZE_T size) {
        MEMORY_REQUEST req = {};
        req.ProcessId = processId;
        req.Address = address;
        req.Buffer = buffer;
        req.Size = size;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x18FF3818,  // IOCTL_WRITE_MEMORY_3 (10x faster)
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        );
    }

    PVOID GetProcessBase(ULONG processId) {
        PFN_REQUEST req = { 0 };
        req.ProcessId = processId;

        DWORD bytesReturned;
        if (DeviceIoControl(
            hDevice,
            0x3A628AFC,  // IOCTL_GET_PEB 
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        )) {
            return req.ProcessBase;
        }
        return nullptr;
    }

    PVOID GetProcessBaseViaPFN(ULONG processId) {
        PFN_REQUEST req = { 0 };
        req.ProcessId = processId;

        DWORD bytesReturned;
        if (DeviceIoControl(
            hDevice,
            0x537C54B4,  // IOCTL_GET_PFN_BASE
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        )) {
            return req.ProcessBase;
        }
        return nullptr;
    }

    bool SetCR3Context(ULONG processId) {
        CR3_CONTEXT req = { 0 };
        req.ProcessId = processId;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x3CC541EF,  // IOCTL_SET_CR3
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        );
    }

    ULONG64 GetCR3(ULONG processId) {
        CR3_CONTEXT req = { 0 };
        req.ProcessId = processId;

        DWORD bytesReturned;
        if (DeviceIoControl(
            hDevice,
            0x3CCDAC80,  // IOCTL_GET_CR3
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        )) {
            return req.TargetCR3;
        }
        return 0;
    }
    PVOID PatternScan(PVOID baseAddress, SIZE_T size, const char* pattern, const char* mask) {
        PATTERN_SCAN_REQUEST req = { 0 };
        req.BaseAddress = baseAddress;
        req.Size = size;
        req.Pattern = (PVOID)pattern;
        req.Mask = (PCHAR)mask;

        DWORD bytesReturned;
        if (DeviceIoControl(
            hDevice,
            0x635474F5,  // IOCTL_PATTERN_SCAN
            &req,
            sizeof(req),
            &req,
            sizeof(req),
            &bytesReturned,
            nullptr
        )) {
            return req.Result;
        }
        return nullptr;
    }

    bool HideProcess(ULONG processId) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x45FB0E3F,  // IOCTL_HIDE_PROCESS
            &processId,
            sizeof(processId),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );
    }

    bool UnlinkProcess(ULONG processId) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x41926E27,  // IOCTL_UNLINK_PROCESS
            &processId,
            sizeof(processId),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );
    }

    bool MouseEvent(double x, double y, MouseFlags ButtonFlags) {
        if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
            return false;

        NF_MOUSE_REQUEST MouseRequest{};
        MouseRequest.x = (int)x;
        MouseRequest.y = (int)y;
        MouseRequest.ButtonFlags = (short)ButtonFlags;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            0x23FACC00,
            &MouseRequest,
            sizeof(NF_MOUSE_REQUEST),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );
    }
};




class GameCheat {
private:
    XRCDriver driver;
    ULONG gamePID;
    PVOID gameBase;
    ULONG64 gameCR3;

public:
    XRCDriver& GetDriver() { return driver; }

    bool Initialize(const wchar_t* processName) {
        wprintf(L"[+] Initializing driver...\n");

        if (!driver.Initialize()) {
            wprintf(L"[-] Driver initialization failed! Could not open device.\n");
            DWORD err = GetLastError();
            wprintf(L"[!] GetLastError(): %lu\n", err);
            return false;
        }

        wprintf(L"[+] Searching for process: %s\n", processName);
        gamePID = FindProcessByName(processName);
        if (!gamePID) {
            wprintf(L"[-] Process %s not found!\n", processName);
            return false;
        }
        wprintf(L"[+] Found process %s with PID: %lu\n", processName, gamePID);

        wprintf(L"[+] Getting process base via PFN...\n");
        gameBase = driver.GetProcessBaseViaPFN(gamePID);

        if (!gameBase) {
            wprintf(L"[!] PFN-based base retrieval failed, falling back to module GetProcessBase...\n");
            gameBase = driver.GetProcessBase(gamePID);
            if (!gameBase) {
                wprintf(L"[!] PFN-based base retrieval failed, falling back to module snapshot...\n");
                gameBase = (PVOID)GetModuleBase(gamePID, processName);
                if (!gameBase) {
                wprintf(L"[-] Failed to get process base via module snapshot!\n");
                return false;
                }
            }
        }

        wprintf(L"[+] Process base: 0x%p\n", gameBase);

        wprintf(L"[+] Getting CR3 for process...\n");
        gameCR3 = driver.GetCR3(gamePID);
        if (!gameCR3) {
            wprintf(L"[-] Failed to get CR3 for process!\n");
            
        }
        if (gameCR3) {
            wprintf(L"[+] CR3: 0x%llx\n", gameCR3);
        }
        

        wprintf(L"[+] Hiding current process...\n");
        if (!driver.HideProcess(GetCurrentProcessId())) {
            wprintf(L"[!] Failed to hide current process, but continuing...\n");
        }
        else {
            wprintf(L"[+] Process hidden successfully.\n");
        }

        wprintf(L"[+] Initialization complete.\n");
        return true;
    }




    template<typename T>
    T Read(PVOID address) {
        T value = {};

        driver.SetCR3Context(gamePID);
        driver.ReadMemory3(gamePID, address, &value, sizeof(T));

        return value;
    }

    template<typename T>
    void Write(PVOID address, T value) {
        driver.SetCR3Context(gamePID);
        driver.WriteMemory3(gamePID, address, &value, sizeof(T));
    }

    PVOID FindPattern(const char* pattern, const char* mask) {
        return driver.PatternScan(gameBase, 0x10000000, pattern, mask);
    }
};



int main() {
    GameCheat cheat;


    if (!cheat.Initialize(L"VALORANT.exe")) {
        printf("\nFailed to initialize\n");
        return -1;
    }
    else
    {

        printf("\nDriver loaded.\n");
        Sleep(2000);

        int x = 960;
        int y = 540;


        int durationMs = 10000;
        int intervalMs = 50;
        int steps = durationMs / intervalMs;


        int stepX = -5; 
        int stepY = 0;

        printf("\nTesting mouse move\n");
        for (int i = 0; i < steps; ++i) {
            x += stepX;
            y += stepY;
            cheat.GetDriver().MouseEvent(x, y, MouseFlags::None);

            Sleep(intervalMs);
        }

        printf("Mouse move completed.\n");
        Sleep(20000);
    }


    return 0;
}
