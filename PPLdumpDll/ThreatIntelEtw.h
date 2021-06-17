#include <windows.h>

EXTERN_C __declspec(selectany) const GUID MicrosoftWindowsThreatIntelligence = { 0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44} };

#define KERNEL_THREATINT_TASK_ALLOCVM_value 0x1
#define KERNEL_THREATINT_TASK_PROTECTVM_value 0x2
#define KERNEL_THREATINT_TASK_MAPVIEW_value 0x3
#define KERNEL_THREATINT_TASK_QUEUEUSERAPC_value 0x4
#define KERNEL_THREATINT_TASK_SETTHREADCONTEXT_value 0x5
#define KERNEL_THREATINT_TASK_ALLOCVM6_value 0x6
#define KERNEL_THREATINT_TASK_PROTECTVM7_value 0x7
#define KERNEL_THREATINT_TASK_MAPVIEW8_value 0x8
#define KERNEL_THREATINT_TASK_READVM_value 0xb
#define KERNEL_THREATINT_TASK_WRITEVM_value 0xc
#define KERNEL_THREATINT_TASK_READVM13_value 0xd
#define KERNEL_THREATINT_TASK_WRITEVM14_value 0xe
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD_value 0xf
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD16_value 0x10
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS_value 0x11
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS18_value 0x12
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS19_value 0x13
#define KERNEL_THREATINT_TASK_SUSPENDRESUME_PROCESS20_value 0x14
#define KERNEL_THREATINT_TASK_ALLOCVM21_value 0x15
#define KERNEL_THREATINT_TASK_PROTECTVM22_value 0x16
#define KERNEL_THREATINT_TASK_MAPVIEW23_value 0x17
#define KERNEL_THREATINT_TASK_QUEUEUSERAPC24_value 0x18
#define KERNEL_THREATINT_TASK_SETTHREADCONTEXT25_value 0x19
#define KERNEL_THREATINT_TASK_ALLOCVM26_value 0x1a
#define KERNEL_THREATINT_TASK_PROTECTVM27_value 0x1b
#define KERNEL_THREATINT_TASK_MAPVIEW28_value 0x1c


typedef unsigned long UInt32;
typedef unsigned long long UInt64;
typedef unsigned char UInt8;
typedef unsigned short UInt16;
typedef void* Pointer;
typedef void* UnicodeString; // ??


#pragma pack(push, 1)
struct QueueApc_t {
    UInt32  CallingProcessId;
    FILETIME  CallingProcessCreateTime;
    UInt64  CallingProcessStartKey;
    UInt8  CallingProcessSignatureLevel;
    UInt8  CallingProcessSectionSignatureLevel;
    UInt8  CallingProcessProtection;
    UInt32  CallingThreadId;
    FILETIME  CallingThreadCreateTime;
    UInt32  TargetProcessId;
    FILETIME  TargetProcessCreateTime;
    UInt64  TargetProcessStartKey;
    UInt8  TargetProcessSignatureLevel;
    UInt8  TargetProcessSectionSignatureLevel;
    UInt8  TargetProcessProtection;
    UInt32  TargetThreadId;
    FILETIME  TargetThreadCreateTime;
    UInt32  OriginalProcessId;
    FILETIME  OriginalProcessCreateTime;
    UInt64  OriginalProcessStartKey;
    UInt8  OriginalProcessSignatureLevel;
    UInt8  OriginalProcessSectionSignatureLevel;
    UInt8  OriginalProcessProtection;
    UInt8  TargetThreadAlertable;
    Pointer ApcRoutine;
    Pointer ApcArgument1;
    Pointer ApcArgument2;
    Pointer ApcArgument3;
    FILETIME  RealEventTime;
    UInt32  ApcRoutineVadQueryResult;
    Pointer ApcRoutineVadAllocationBase;
    UInt32  ApcRoutineVadAllocationProtect;
    UInt32  ApcRoutineVadRegionType;
    Pointer ApcRoutineVadRegionSize;
    Pointer ApcRoutineVadCommitSize;
    UnicodeString ApcRoutineVadMmfName;
    UInt32  ApcArgument1VadQueryResult;
    Pointer ApcArgument1VadAllocationBase;
    UInt32  ApcArgument1VadAllocationProtect;
    UInt32  ApcArgument1VadRegionType;
    Pointer ApcArgument1VadRegionSize;
    Pointer ApcArgument1VadCommitSize;
    UnicodeString ApcArgument1VadMmfName;
};

struct PageProtect_t {
    UInt32 CallingProcessId;
    FILETIME CallingProcessCreateTime;
    UInt64 CallingProcessStartKey;
    UInt8 CallingProcessSignatureLevel;
    UInt8 CallingProcessSectionSignatureLevel;
    UInt8 CallingProcessProtection;
    UInt32 CallingThreadId;
    FILETIME CallingThreadCreateTime;
    UInt32 TargetProcessId;
    FILETIME TargetProcessCreateTime;
    UInt64 TargetProcessStartKey;
    UInt8 TargetProcessSignatureLevel;
    UInt8 TargetProcessSectionSignatureLevel;
    UInt8 TargetProcessProtection;
    UInt32 OriginalProcessId;
    FILETIME OriginalProcessCreateTime;
    UInt64 OriginalProcessStartKey;
    UInt8 OriginalProcessSignatureLevel;
    UInt8 OriginalProcessSectionSignatureLevel;
    UInt8 OriginalProcessProtection;
    Pointer BaseAddress;
    Pointer RegionSize;
    UInt32 ProtectionMask;
    UInt32 LastProtectionMask;
};

struct SetContext_t {
    UInt32 CallingProcessId;
    FILETIME CallingProcessCreateTime;
    UInt64 CallingProcessStartKey;
    UInt8 CallingProcessSignatureLevel;
    UInt8 CallingProcessSectionSignatureLevel;
    UInt8 CallingProcessProtection;
    UInt32 CallingThreadId;
    FILETIME CallingThreadCreateTime;
    UInt32 TargetProcessId;
    FILETIME TargetProcessCreateTime;
    UInt64 TargetProcessStartKey;
    UInt8 TargetProcessSignatureLevel;
    UInt8 TargetProcessSectionSignatureLevel;
    UInt8 TargetProcessProtection;
    UInt32 TargetThreadId;
    FILETIME TargetThreadCreateTime;
    UInt32 ContextFlags;
    UInt16 ContextMask;
    Pointer Pc;
    Pointer Sp;
    Pointer Lr;
    Pointer Fp;
    Pointer Reg0;
    Pointer Reg1;
    Pointer Reg2;
    Pointer Reg3;
    Pointer Reg4;
    Pointer Reg5;
    Pointer Reg6;
    Pointer Reg7;
    FILETIME RealEventTime;
    UInt32 PcVadQueryResult;
    Pointer PcVadAllocationBase;
    UInt32 PcVadAllocationProtect;
    UInt32 PcVadRegionType;
    Pointer PcVadRegionSize;
    Pointer PcVadCommitSize;
    UnicodeString PcVadMmfName;
};

struct Alloc_t {
    UInt32 CallingProcessId;
    FILETIME CallingProcessCreateTime;
    UInt64 CallingProcessStartKey;
    UInt8 CallingProcessSignatureLevel;
    UInt8 CallingProcessSectionSignatureLevel;
    UInt8 CallingProcessProtection;
    UInt32 CallingThreadId;
    FILETIME CallingThreadCreateTime;
    UInt32 TargetProcessId;
    FILETIME TargetProcessCreateTime;
    UInt64 TargetProcessStartKey;
    UInt8 TargetProcessSignatureLevel;
    UInt8 TargetProcessSectionSignatureLevel;
    UInt8 TargetProcessProtection;
    UInt32 OriginalProcessId;
    FILETIME OriginalProcessCreateTime;
    UInt64 OriginalProcessStartKey;
    UInt8 OriginalProcessSignatureLevel;
    UInt8 OriginalProcessSectionSignatureLevel;
    UInt8 OriginalProcessProtection;
    Pointer BaseAddress;
    Pointer RegionSize;
    UInt32 AllocationType;
    UInt32 ProtectionMask;
};

struct MapView_t {
    UInt32 CallingProcessId;
    FILETIME CallingProcessCreateTime;
    UInt64 CallingProcessStartKey;
    UInt8 CallingProcessSignatureLevel;
    UInt8 CallingProcessSectionSignatureLevel;
    UInt8 CallingProcessProtection;
    UInt32 CallingThreadId;
    FILETIME CallingThreadCreateTime;
    UInt32 TargetProcessId;
    FILETIME TargetProcessCreateTime;
    UInt64 TargetProcessStartKey;
    UInt8 TargetProcessSignatureLevel;
    UInt8 TargetProcessSectionSignatureLevel;
    UInt8 TargetProcessProtection;
    Pointer BaseAddress;
    Pointer ViewSize;
    UInt32 AllocationType;
    UInt32 ProtectionMask;
};

#pragma pack(pop)
