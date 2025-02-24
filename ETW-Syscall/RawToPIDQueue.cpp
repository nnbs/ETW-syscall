#include "EtwReceiver.h"
#include <memory>
#include <map>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>

// start key -> function -> count
static std::map<ULONG64, std::map<PVOID, int> > TIDEvents;

// TID -> start key
static std::map<int, ULONG64> TIDStartKey;

// start key -> process name
static std::map<ULONG64, std::wstring> StartKeyProcessName;

static HANDLE hThread;
static int stop = 0;

std::wstring GetProcessNameByPid(DWORD pPid) {
    HANDLE hProceesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProceesSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(pe32);
        BOOL hProcess = Process32First(hProceesSnap, &pe32);
        while (hProcess)
        {
            //printf("%ws %d\n", pe32.szExeFile, pe32.th32ProcessID);
            if (pe32.th32ProcessID == pPid) {
                CloseHandle(hProceesSnap);
                return std::wstring(pe32.szExeFile);
            }
            hProcess = Process32Next(hProceesSnap, &pe32);
        }
        CloseHandle(hProceesSnap);
    }
    return std::wstring(L"unknown");
}

typedef DWORD PROCESSINFOCLASS;
typedef NTSTATUS (*pfn_NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef struct _PROCESS_TELEMETRY_ID_INFORMATION {
    ULONG HeaderSize;
    ULONG ProcessId;
    ULONG64 ProcessStartKey;
    ULONG64 CreateTime;
    ULONG64 CreateInterruptTime;
    ULONG64 CreateUnbiasedInterruptTime;
    ULONG64 ProcessSequenceNumber;
    ULONG64 SessionCreateTime;
    ULONG SessionId;
    ULONG BootId;
    ULONG ImageChecksum;
    ULONG ImageTimeDateStamp;
    ULONG UserSidOffset;
    ULONG ImagePathOffset;
    ULONG PackageNameOffset;
    ULONG RelativeAppNameOffset;
    ULONG CommandLineOffset;
} PROCESS_TELEMETRY_ID_INFORMATION, * PPROCESS_TELEMETRY_ID_INFORMATION;


#include <unordered_map>
class DevicePathConverter {
private:
    std::unordered_map<std::wstring, std::wstring> driveMappingCache;

    void updateDriveMapping(const std::wstring& devicePath) {
        for (const auto& entry : driveMappingCache) {
            if (devicePath.find(entry.first) == 0) {
                return;
            }
        }


        driveMappingCache.clear();
        wchar_t volumePath[MAX_PATH];
        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            std::wstring driveLetter = std::wstring(1, letter) + L":";
            if (QueryDosDeviceW(driveLetter.c_str(), volumePath, MAX_PATH)) {
                driveMappingCache[volumePath] = driveLetter;
            }
        }
    }

public:
    std::wstring deviceToDosPath(const std::wstring& devicePath) {
        updateDriveMapping(devicePath);

        for (const auto& entry : driveMappingCache) {
            const std::wstring& volumePath = entry.first;
            if (devicePath.find(volumePath) == 0) {
                return entry.second + devicePath.substr(volumePath.length());
            }
        }
        return devicePath;
    }
};


static DevicePathConverter gDevicePathConverter;

void ThreadTerminated(DWORD ThreadId) {
    TIDStartKey.erase(ThreadId);
}

ULONG64 WINAPI NewProcessAdd(DWORD ThreadId) {
    static pfn_NtQueryInformationProcess fn_NtQueryInformationProcess = NULL;
    if (fn_NtQueryInformationProcess == NULL) {
        HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
        if (hNtDll != NULL) {
            fn_NtQueryInformationProcess = (pfn_NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        }
    }

    if (TIDStartKey.find(ThreadId) == TIDStartKey.end()) {
        HANDLE ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, ThreadId);
        if (ThreadHandle != INVALID_HANDLE_VALUE && ThreadHandle != NULL) {
            DWORD ProcessId = GetProcessIdOfThread(ThreadHandle);
            if (ProcessId == GetCurrentProcessId()) {
                CloseHandle(ThreadHandle);
                return 0;
            }
            if (ProcessId != NULL) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
                if (hProcess != INVALID_HANDLE_VALUE && hProcess != NULL) {
                    PPROCESS_TELEMETRY_ID_INFORMATION pTelemetryInfo = NULL;
                    ULONG ret = 0;
                    NTSTATUS status = fn_NtQueryInformationProcess(hProcess, 64 /*ProcessTelemetryIdInformation*/, pTelemetryInfo, 0, &ret);
                    if ((status == 0xc0000004) || (status == 0x80000005)) {
                        pTelemetryInfo = (PPROCESS_TELEMETRY_ID_INFORMATION)malloc(ret);
                        if (pTelemetryInfo != NULL) {
                            status = fn_NtQueryInformationProcess(hProcess, 64 /*ProcessTelemetryIdInformation*/, pTelemetryInfo, ret, &ret);
                            if (status == 0) {
                                gDevicePathConverter.deviceToDosPath((wchar_t*)((BYTE*)pTelemetryInfo + pTelemetryInfo->ImagePathOffset));

                                TIDStartKey[ThreadId] = pTelemetryInfo->ProcessStartKey;
                                StartKeyProcessName[pTelemetryInfo->ProcessStartKey] = (wchar_t*)((BYTE*)pTelemetryInfo + pTelemetryInfo->ImagePathOffset);
                            }
                            else {
                                printf("NtQueryInformationProcess failed with status %08x, %d\n", status, ret);
                            }
                            free(pTelemetryInfo);
                        }
                    }
                    else {
                        printf("NtQueryInformationProcess failed with status %08x, %d\n", status, ret);
                    }

                    CloseHandle(hProcess);
                }
            }
            CloseHandle(ThreadHandle);
        }
    }

    return TIDStartKey[ThreadId];

}


DWORD WINAPI RawToTID_Thread(LPVOID lpParam) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    // sysInfo.dwNumberOfProcessors;

    // cpuid -> startkey
    std::map<int, ULONG64> coreToTIDMap;

    printf("Start RawToTID_Thread\n");

    TIDEvents.clear();
    do {

        std::shared_ptr<EventObject> pEvent = PopEventQueue();
        if (pEvent) {
            int cpuid = pEvent->CPUId;

            switch (pEvent->type) {
            case EventType::CSwitch:
                do {
                    ULONG64 startkey = NewProcessAdd(pEvent->UserData.CSwitch.NewThreadId);
                    //printf("NewProcessAdd %d: %lld\n", pEvent->UserData.CSwitch.NewThreadId, startkey);
                    coreToTIDMap[cpuid] = startkey;
                } while (0);

                break;
            case EventType::SysCall:
                do {
                    ULONG64 startkey = coreToTIDMap[cpuid];
                    if (startkey) {
                        TIDEvents[startkey][pEvent->UserData.SysCall.functionAddress]++;
                    }
                } while (0);
                break;
            case EventType::ThreadTerminate:
                ThreadTerminated(pEvent->UserData.ThreadTerminate.ThreadId);
                break;
            }
        }
        else {
            printf("EndThread!!\n");
            break;
        }


   } while(true);

    return 0;
}

void Start_RawToPID() {
    DWORD dwThrId = 0;

    stop = 0;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RawToTID_Thread, (LPVOID)NULL, 0, &dwThrId);
    if (hThread == 0) {
        printf("Create thread fail");
    }
}

void Stop_RawToPID() {

    stop = 1;

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }


    HANDLE hFile = CreateFile(L"ProcessCallAPI.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {

        for (auto it = TIDEvents.begin(); it != TIDEvents.end(); it = next(it)) {
            //printf("%d: %lld\n", it->first, it->second.size());
            char buffer[1024];
            sprintf_s(buffer, "[%ws]\n", StartKeyProcessName[it->first].c_str());
            WriteFile(hFile, buffer, (DWORD)strlen(buffer), NULL, NULL);

            for (auto it2 = it->second.begin(); it2 != it->second.end(); it2 = next(it2)) {
                //printf("    %p: %d\n", it2->first, it2->second);

                sprintf_s(buffer, "    %p: %d\n", it2->first, it2->second);
                WriteFile(hFile, buffer, (DWORD)strlen(buffer), NULL, NULL);
            }

        }
        CloseHandle(hFile);
    }
    printf("======\n");

}

