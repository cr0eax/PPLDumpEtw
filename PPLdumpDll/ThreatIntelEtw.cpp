#include <windows.h>
#include <evntrace.h>
#include <Evntcons.h>
#include <tlhelp32.h>

#include "ThreatIntelEtw.h"

void LogToConsole(LPCWSTR pwszFormat, ...);

BOOL ProcessGetPIDFromName(LPWSTR pwszProcessName, DWORD pdwProcessId)
{
    pwszProcessName[0] = '?'; pwszProcessName[1] = '\0';

    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = { 0 };
    DWORD dwProcessId = 0;
    DWORD dwMatchCount = 0;
    BOOL bMatch = FALSE;

    if ((hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
    {
        goto end;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        goto end;
    }

    do
    {
        if (pdwProcessId == pe32.th32ProcessID)
        {
            wcscpy_s(pwszProcessName, 256, pe32.szExeFile);
            bMatch = TRUE;
            break;
        }

    } while (Process32Next(hProcessSnap, &pe32));
end:
    if (hProcessSnap)
        CloseHandle(hProcessSnap);

    return bMatch;
}

WCHAR targetProcessname[MAX_PATH] = {};
WCHAR sourceProcessname[MAX_PATH] = {};
WCHAR originalProcessname[MAX_PATH] = {};

bool IsBlackListedProcess(LPWSTR) {
    return false;
    //return wcscmp(targetProcessname, L"firefox.exe") == 0 || wcscmp(targetProcessname, L"slack.exe") == 0;
}

void LogProtection(LPCWSTR szName, LPVOID pData) {
    PageProtect_t* pEvent = ((PageProtect_t*)pData);
    DWORD dwProtection = pEvent->ProtectionMask;
    if (dwProtection == PAGE_EXECUTE_READWRITE || dwProtection == PAGE_EXECUTE || dwProtection == PAGE_EXECUTE_READ || dwProtection == PAGE_EXECUTE_WRITECOPY) {
        ProcessGetPIDFromName(targetProcessname, pEvent->TargetProcessId);
        ProcessGetPIDFromName(sourceProcessname, pEvent->CallingProcessId);
        ProcessGetPIDFromName(originalProcessname, pEvent->OriginalProcessId);
        if (!IsBlackListedProcess(sourceProcessname) && pEvent->TargetProcessId != pEvent->CallingProcessId) {
            LogToConsole(L"[%s] - call:%s(%i) target:%s(%i) orig:%s(%i) base:%p size:%p prot:%08x prev_prot:%08x\n",
                szName,
                sourceProcessname, pEvent->CallingProcessId,
                targetProcessname, pEvent->TargetProcessId,
                originalProcessname, pEvent->OriginalProcessId,
                pEvent->BaseAddress,
                pEvent->RegionSize,
                pEvent->ProtectionMask,
                pEvent->LastProtectionMask
            );
        }
    }
}

void LogApc(LPCWSTR szName, LPVOID pData) {
    QueueApc_t* pEvent = ((QueueApc_t*)pData);

    ProcessGetPIDFromName(targetProcessname, pEvent->TargetProcessId);
    ProcessGetPIDFromName(sourceProcessname, pEvent->CallingProcessId);
    ProcessGetPIDFromName(originalProcessname, pEvent->OriginalProcessId);

    if (!IsBlackListedProcess(sourceProcessname) && pEvent->TargetProcessId != pEvent->CallingProcessId) {
        LogToConsole(L"[%s] - call:%s(%i) target:%s(%i) orig:%s(%i) ApcRoutine:%p arg1:%p arg2:%p arg3:%p\n",
            szName,
            sourceProcessname, pEvent->CallingProcessId,
            targetProcessname, pEvent->TargetProcessId,
            originalProcessname, pEvent->OriginalProcessId,
            pEvent->ApcRoutine,
            pEvent->ApcArgument1,
            pEvent->ApcArgument2,
            pEvent->ApcArgument3
        );
    }
}

void LogSetThreadContext(LPCWSTR szName, LPVOID pData) {
    SetContext_t* pEvent = ((SetContext_t*)pData);

    ProcessGetPIDFromName(targetProcessname, pEvent->TargetProcessId);
    ProcessGetPIDFromName(sourceProcessname, pEvent->CallingProcessId);

    if (!IsBlackListedProcess(sourceProcessname) && pEvent->TargetProcessId != pEvent->CallingProcessId) {
        LogToConsole(L"[%s] - call:%s(%i) target:%s(%i) Pc:%p\n",
            szName,
            sourceProcessname, pEvent->CallingProcessId,
            targetProcessname, pEvent->TargetProcessId,
            pEvent->Pc
        );
    }
}

void LogAlloc(LPCWSTR szName, LPVOID pData) {
    Alloc_t* pEvent = ((Alloc_t*)pData);
    DWORD dwProtection = pEvent->ProtectionMask & 0xff;

    if (dwProtection == PAGE_EXECUTE_READWRITE || dwProtection == PAGE_EXECUTE || dwProtection == PAGE_EXECUTE_READ || dwProtection == PAGE_EXECUTE_WRITECOPY) {
        ProcessGetPIDFromName(targetProcessname, pEvent->TargetProcessId);
        ProcessGetPIDFromName(sourceProcessname, pEvent->CallingProcessId);
        ProcessGetPIDFromName(originalProcessname, pEvent->OriginalProcessId);

        if (!IsBlackListedProcess(sourceProcessname) && pEvent->TargetProcessId != pEvent->CallingProcessId) {
            LogToConsole(L"[%s] - call:%s(%i) target:%s(%i) orig:%s(%i) base:%p size:%p type:%x prot:%x\n",
                szName,
                sourceProcessname, pEvent->CallingProcessId,
                targetProcessname, pEvent->TargetProcessId,
                originalProcessname, pEvent->OriginalProcessId,
                pEvent->BaseAddress,
                pEvent->RegionSize,
                pEvent->AllocationType,
                pEvent->ProtectionMask
            );
        }
    }
}

void LogMapView(LPCWSTR szName, LPVOID pData) {
    MapView_t* pEvent = ((MapView_t*)pData);
    DWORD dwProtection = pEvent->ProtectionMask & 0xff;

    if (dwProtection == PAGE_EXECUTE_READWRITE || dwProtection == PAGE_EXECUTE || dwProtection == PAGE_EXECUTE_READ || dwProtection == PAGE_EXECUTE_WRITECOPY) {
        ProcessGetPIDFromName(targetProcessname, pEvent->TargetProcessId);
        ProcessGetPIDFromName(sourceProcessname, pEvent->CallingProcessId);

        if (!IsBlackListedProcess(sourceProcessname) && pEvent->TargetProcessId != pEvent->CallingProcessId) {
            LogToConsole(L"[%s] - call:%s(%i) target:%s(%i) base:%p size:%p type:%x prot:%x\n",
                szName,
                sourceProcessname, pEvent->CallingProcessId,
                targetProcessname, pEvent->TargetProcessId,
                pEvent->BaseAddress,
                pEvent->ViewSize,
                pEvent->AllocationType,
                pEvent->ProtectionMask
            );
        }
    }
}

static void NTAPI ProcessEvent(PEVENT_RECORD EventRecord) {
    PEVENT_HEADER eventHeader = &EventRecord->EventHeader;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;

    switch (eventDescriptor->Id) {
        case KERNEL_THREATINT_TASK_ALLOCVM_value:
            LogAlloc(L"ALLOCVM", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM_value:
            LogProtection(L"PROTECTVM", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW_value:
            LogMapView(L"MAPVIEW", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_value:
            LogApc(L"QUEUEUSERAPC", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_value:
            LogSetThreadContext(L"SETTHREADCONTEXT", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_ALLOCVM6_value:
            LogAlloc(L"ALLOCVM6", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM7_value:
            LogProtection(L"PROTECTVM7", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW8_value:
            LogMapView(L"MAPVIEW8", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_READVM_value:
            LogToConsole(L"[READVM] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_WRITEVM_value:
            LogToConsole(L"[WRITEVM] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_READVM13_value:
            LogToConsole(L"[READVM13] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_WRITEVM14_value:
            LogToConsole(L"[WRITEVM14] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD_value:
            LogToConsole(L"[SUSPENDRESUME_THREAD] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD16_value:
            LogToConsole(L"[SUSPENDRESUME_THREAD16] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS_value:
            LogToConsole(L"[TASK_SUSPENDRESUME_PROCESS] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS18_value:
            LogToConsole(L"[TASK_SUSPENDRESUME_PROCESS18] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS19_value:
            LogToConsole(L"[TASK_SUSPENDRESUME_PROCESS19] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS20_value:
            LogToConsole(L"[TASK_SUSPENDRESUME_PROCESS20] - %08x %s\n", eventHeader->ProcessId, targetProcessname);
            break;
        case KERNEL_THREATINT_TASK_ALLOCVM21_value:
            LogAlloc(L"ALLOCVM21", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM22_value:
            LogProtection(L"PROTECTVM22", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW23_value:
            LogMapView(L"MAPVIEW23", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC24_value:
            LogApc(L"QUEUEUSERAPC_KERNEL", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT25_value:
            LogSetThreadContext(L"SETTHREADCONTEXT25", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_ALLOCVM26_value:
            LogAlloc(L"ALLOCVM26", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM27_value:
            LogProtection(L"PROTECTVM22", EventRecord->UserData);
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW28_value:
            LogMapView(L"MAPVIEW28", EventRecord->UserData);
            break;
        default:
            LogToConsole(L"[UNKNOWN_EVENT] - id:%08x\n", eventDescriptor->Id);
    }
}

void TraceThread() {
    TRACEHANDLE hTrace = 0;
    ULONG result, bufferSize;
    EVENT_TRACE_LOGFILEA trace;
    EVENT_TRACE_PROPERTIES* traceProp;

    LogToConsole(L"[*] TraceThread started\n");

    const char* name = "MicrosoftThreatLogger";

    memset(&trace, 0, sizeof(EVENT_TRACE_LOGFILEA));
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.LoggerName = (LPSTR)name;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEvent;

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (strlen(name) + 1) * sizeof(CHAR);

    traceProp = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.ClientContext = 1;
    traceProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
    traceProp->LogFileNameOffset = 0;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    if ((result = StartTraceA(&hTrace, name, traceProp)) != ERROR_SUCCESS) {
        if (ERROR_ALREADY_EXISTS == result) {
            PEVENT_TRACE_PROPERTIES petpStop = (PEVENT_TRACE_PROPERTIES)LocalAlloc(LPTR, bufferSize);
            petpStop->Wnode.BufferSize = bufferSize;
            petpStop->LoggerNameOffset = 0;
            petpStop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            result = StopTraceA(hTrace, name, petpStop);
            if (result) {
                LogToConsole(L"[!] StopTraceA: %08x\n", result);
                return;
            }
            result = StartTraceA(&hTrace, name, traceProp);
            if (result) {
                LogToConsole(L"[!] StartTraceA: %08x\n", result);
                return;
            }
        } else {
            LogToConsole(L"[!] StartTraceA: %08x\n", result);
            return;
        }
    }

    if ((result = EnableTraceEx(&MicrosoftWindowsThreatIntelligence, NULL, hTrace, 1, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL)) != ERROR_SUCCESS) {
        LogToConsole(L"[!] Error EnableTraceEx trace: %08x\n", result);
        return;
    }

    hTrace = OpenTraceA(&trace);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        LogToConsole(L"[!] OpenTrace\n");
        return;
    }

    result = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        LogToConsole(L"[!] ProcessTrace\n");
        return;
    }

    return;
}