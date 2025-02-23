#include "EtwReceiver.h"
#include <memory>
#include <map>

// PID -> function -> count
static std::map<int, std::map<PVOID, int> > PIDEvents;

static HANDLE hThread;
static int stop = 0;

struct CSwitch
{
    UINT32 NewThreadId;						// + 0x00
    UINT32 OldThreadId;						// + 0x04
    INT8 NewThreadPriority;					// + 0x08
    INT8 OldThreadPriority;					// + 0x09
    UINT8 PreviousCState;					// + 0x0A
    INT8 SpareByte;							// + 0x0B
    INT8 OldThreadWaitReason;				// + 0x0C
    INT8 OldThreadWaitMode;					// + 0x0D
    INT8 OldThreadState;					// + 0x0E
    INT8 OldThreadWaitIdealProcessor;		// + 0x0F
    UINT32 NewThreadWaitTime;				// + 0x10
    UINT32 Reserved;						// + 0x14
};

DWORD WINAPI RawToPIDThread(LPVOID lpParam) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    // sysInfo.dwNumberOfProcessors;

    std::map<int, int> coreToPIDMap;
    printf("Start RawToPIDThread\n");
    do {
        if (IsEmpty()) {
            if (stop == 1) {
                break;
            }
            continue;
        }
        std::shared_ptr<EventObject> pEvent = PopEventQueue();
        if (pEvent) {
            int cpuid = pEvent->CPUId;

            switch (pEvent->type) {
            case EventType::CSwitch:
                do {
                    struct CSwitch* pCSwitch = (struct CSwitch*)pEvent->UserData.Common.UserData;
                    coreToPIDMap[cpuid] = pCSwitch->NewThreadId;
                    free(pEvent->UserData.Common.UserData);
                } while (0);

                break;
            case EventType::SysCall:
                int PID = coreToPIDMap[cpuid];
                if (PID) {
                    PIDEvents[PID][pEvent->UserData.SysCall.functionAddress]++;
                }
                break;
            }
        }


   } while(true);

    return 0;
}

void Start_RawToPID() {
    DWORD dwThrId = 0;

    stop = 0;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RawToPIDThread, (LPVOID)NULL, 0, &dwThrId);
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

    for (auto it = PIDEvents.begin(); it != PIDEvents.end(); it++) {
        printf("%d\n", it->first);
    }


}

