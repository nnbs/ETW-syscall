#include <windows.h>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>

#include "EtwReceiver.h"
#include "ThreadSafeQueue.h"

// cpuid -> queue
ThreadSafeQueue gEventQueue;

std::shared_ptr<EventObject> PopEventQueue() {
    return gEventQueue.pop();
}

bool IsEmpty() {
    return gEventQueue.empty();
}

// Use NT Kernel Logger for tracing
#define NT_KERNEL_LOGGER L"NT Kernel Logger"

void WINAPI EventCallback(PEVENT_RECORD EventRecord)
{
    std::shared_ptr<EventObject> obj = std::make_shared<EventObject>();
    obj->CPUId = EventRecord->BufferContext.ProcessorNumber;

    switch (EventRecord->EventHeader.EventDescriptor.Opcode) {
    case 51: // sys-entry
        obj->type = EventType::SysCall;
        obj->UserData.SysCall.functionAddress = (PVOID)EventRecord->UserData;
        //printf("%p\n", (PVOID)EventRecord->UserData);
        gEventQueue.push(obj);

        break;
    case 36: // CSwitch
        obj->type = EventType::CSwitch;
        obj->UserData.Common.UserDataLength = EventRecord->UserDataLength;
        obj->UserData.Common.UserData = malloc(EventRecord->UserDataLength);
        if (obj->UserData.Common.UserData) {
            memcpy(obj->UserData.Common.UserData, EventRecord->UserData, EventRecord->UserDataLength);
            gEventQueue.push(obj);
        }

        break;
    }

}



DWORD WINAPI ProcessTraceThread(LPVOID lpParam) {
    TRACEHANDLE hConsumer = (TRACEHANDLE)lpParam;

    ProcessTrace(&hConsumer, 1, NULL, NULL);
    return 0;
}

static HANDLE hThread = NULL;
static TRACEHANDLE hConsumerTrace = NULL;
PEVENT_TRACE_PROPERTIES pEtwProp = NULL;

bool StartEtwTrace() {

    EVENT_TRACE_LOGFILE etwLogFile = { 0 };
    wchar_t providerName[] = KERNEL_LOGGER_NAME;
    DWORD dwCbProvName = 0,
        dwEtwPropSize = 0;
    TRACEHANDLE hTrace = NULL;

    BOOL bRetVal = FALSE;
    DWORD dwLastErr = 0;

    dwCbProvName = (DWORD)(wcslen(providerName) + 1) * sizeof(TCHAR);

    // Allocate the memory for the ETW data structure
    dwEtwPropSize = sizeof(EVENT_TRACE_PROPERTIES) + dwCbProvName;
    pEtwProp = (PEVENT_TRACE_PROPERTIES)new BYTE[dwEtwPropSize];
    RtlZeroMemory(pEtwProp, dwEtwPropSize);

    pEtwProp->Wnode.ClientContext = 1;
    pEtwProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pEtwProp->Wnode.Guid = SystemTraceControlGuid;
    pEtwProp->Wnode.BufferSize = dwEtwPropSize;
    RtlCopyMemory(((LPBYTE)pEtwProp + sizeof(EVENT_TRACE_PROPERTIES)), providerName, dwCbProvName);

    bRetVal = ControlTrace(NULL, providerName, pEtwProp, EVENT_TRACE_CONTROL_STOP);
    if (bRetVal != ERROR_WMI_INSTANCE_NOT_FOUND) {
        DWORD dwOffset = FIELD_OFFSET(EVENT_TRACE_PROPERTIES, BufferSize);
        RtlZeroMemory((LPBYTE)pEtwProp + dwOffset, dwEtwPropSize - dwOffset);
    }
    pEtwProp->EnableFlags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_SYSTEMCALL;
    pEtwProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pEtwProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);


    wprintf(L"Initializing the ETW Consumer... ");
    bRetVal = StartTrace(&hTrace, providerName, pEtwProp);

    if (bRetVal == ERROR_SUCCESS) {
        RtlZeroMemory(&etwLogFile, sizeof(EVENT_TRACE_LOGFILE));
        etwLogFile.LoggerName = (LPWSTR)providerName;
        etwLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        etwLogFile.EventRecordCallback = EventCallback;

        hConsumerTrace = OpenTrace(&etwLogFile);
        dwLastErr = GetLastError();
        bRetVal = (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE) ? ERROR_SUCCESS : dwLastErr;
    }

    if (bRetVal == ERROR_SUCCESS) {
        DWORD dwThrId = 0;

        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProcessTraceThread, (LPVOID)hConsumerTrace, 0, &dwThrId);
        if (hThread == 0) {
            printf("Create thread fail");
            return false;
        }
    }
    else
        printf("Error %d\r\n", bRetVal);


    return bRetVal == ERROR_SUCCESS;
}

void StopEtwTrace() {
    BOOL bRetVal = FALSE;

    // Stop our Kernel Logger consumer
    if (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        bRetVal = ControlTrace(hConsumerTrace, NULL, pEtwProp, EVENT_TRACE_CONTROL_STOP);
        delete pEtwProp;
        pEtwProp = NULL;
    }

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        hThread = NULL;
    }

    gEventQueue.shutdown();
}

