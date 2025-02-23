#pragma once


#include <map>
#include <queue>
#include <Windows.h>
#include <memory>

enum EventType {
    SysCall = 1,
    CSwitch,
};

typedef struct __EventObject {
    EventType type;
    int CPUId;
    union {
        struct SysCall {
            PVOID functionAddress;
        } SysCall;

        struct Common {
            PVOID UserData;
            USHORT UserDataLength;
        }Common;
    }UserData;

}EventObject, * pEventObject;


bool StartEtwTrace();
void StopEtwTrace();

std::shared_ptr<EventObject> PopEventQueue();
bool IsEmpty();




void Start_RawToPID();
void Stop_RawToPID();


