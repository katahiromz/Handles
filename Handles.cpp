// Handles.c --- List the kernel handles of the process
// Copyright (C) 2020 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
// This file is public domain software.

#ifndef UNICODE
    #define UNICODE
#endif

#include <windows.h>
#include <cstdio>
#include "Auto.hpp"

static void
show_help(void)
{
    printf("Shows the kernel handles of the specified process\n");
    printf("\n");
    printf("Usage: handles [pid]\n");
}

static void
show_version(void)
{
    printf("handles ver.0.6 by katahiromz\n");
}

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef LONG NTSTATUS;
#define NTAPI __stdcall

typedef NTSTATUS (NTAPI *FN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);
typedef NTSTATUS (NTAPI *FN_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options);
typedef NTSTATUS (NTAPI *FN_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

template <typename T>
T DoGetProc(T& fn, HINSTANCE hInst, LPCSTR name)
{
    fn = reinterpret_cast<T>(GetProcAddress(hInst, name));
    return fn;
}

static FN_NtQuerySystemInformation s_pNtQuerySystemInformation;
static FN_NtDuplicateObject s_pNtDuplicateObject;
static FN_NtQueryObject s_pNtQueryObject;

#define NtQuerySystemInformation (*s_pNtQuerySystemInformation)
#define NtDuplicateObject (*s_pNtDuplicateObject)
#define NtQueryObject (*s_pNtQueryObject)

int DoMain(int argc, wchar_t **wargv)
{
    if (argc < 2 || lstrcmpW(wargv[1], L"--help") == 0)
    {
        show_help();
        return EXIT_SUCCESS;
    }

    if (lstrcmpW(wargv[1], L"--version") == 0)
    {
        show_version();
        return EXIT_SUCCESS;
    }

    ULONG pid = wcstoul(wargv[1], NULL, 0);
    AutoCloseHandle hProcess(OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid));
    if (!hProcess)
    {
        printf("Cannot open process %lu", pid);
        return EXIT_FAILURE;
    }

    NTSTATUS status;

    AutoFree<SYSTEM_HANDLE_INFORMATION> pHandleInfo(0x10000);
    for (;;)
    {
        status = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, pHandleInfo.size(), NULL);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        if (!pHandleInfo.resize(pHandleInfo.size() * 2))
        {
            printf("Out of memory\n");
            return EXIT_FAILURE;
        }
    }

    if (!NT_SUCCESS(status))
    {
        printf("NtQuerySystemInformation failed!\n");
        return EXIT_FAILURE;
    }

    for (ULONG i = 0; i < pHandleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE SystemHandle = pHandleInfo->Handles[i];

        if (SystemHandle.ProcessId != pid)
            continue;

        AutoCloseHandle hDuplicate(NULL);
        status = NtDuplicateObject(hProcess,
                                   (HANDLE)(ULONG_PTR)SystemHandle.Handle,
                                   GetCurrentProcess(),
                                   &hDuplicate, 0, 0, 0);
        if (!NT_SUCCESS(status))
        {
            if (status == 0xC00000BB)
                printf("[%#x] (not supported)\n", SystemHandle.Handle);
            else
                printf("[%#x] error: status: 0x%08lX\n", SystemHandle.Handle, status);
            continue;
        }

        AutoFree<OBJECT_TYPE_INFORMATION> TypeInfo(0x1000);
        status = NtQueryObject(hDuplicate, ObjectTypeInformation, TypeInfo, TypeInfo.size(), NULL);
        if (!NT_SUCCESS(status))
        {
            if (status == 0xC00000BB)
                printf("[%#x] (not supported)\n", SystemHandle.Handle);
            else
                printf("[%#x] error: status: 0x%08lX\n", SystemHandle.Handle, status);
            continue;
        }

        if (SystemHandle.GrantedAccess == 0x0012019f)
        {
            printf("[%#x] %.*S: (did not get name)\n", SystemHandle.Handle,
                   TypeInfo->Name.Length / 2, TypeInfo->Name.Buffer);
            continue;
        }

        ULONG cbLength = 0x1000;
        AutoFree<UNICODE_STRING> NameInfo(cbLength);
        status = NtQueryObject(hDuplicate, ObjectNameInformation, NameInfo, cbLength, &cbLength);
        if (!NT_SUCCESS(status))
        {
            NameInfo.resize(cbLength);

            status = NtQueryObject(hDuplicate, ObjectNameInformation, NameInfo, cbLength, NULL);
            if (!NT_SUCCESS(status))
            {
                printf("[%#x] %.*S: (could not get name)\n", SystemHandle.Handle,
                       TypeInfo->Name.Length / 2, TypeInfo->Name.Buffer);
                continue;
            }
        }

        UNICODE_STRING Name = *(PUNICODE_STRING)NameInfo;

        if (Name.Length)
        {
            /* The object has a name. */
            printf("[%#x] %.*S: %.*S\n", SystemHandle.Handle,
                   TypeInfo->Name.Length / 2, TypeInfo->Name.Buffer,
                   Name.Length / 2, Name.Buffer);
        }
        else
        {
            /* No name. */
            printf("[%#x] %.*S: (unnamed)\n", SystemHandle.Handle,
                   TypeInfo->Name.Length / 2, TypeInfo->Name.Buffer);
        }
    }

    return EXIT_SUCCESS;
}

int wmain(int argc, wchar_t **wargv)
{
    HINSTANCE hNTDLL = LoadLibraryA("ntdll.dll");
    if (!hNTDLL)
    {
        printf("Cannot load ntdll.dll\n");
        return EXIT_FAILURE;
    }

    if (!DoGetProc(s_pNtQuerySystemInformation, hNTDLL, "NtQuerySystemInformation") ||
        !DoGetProc(s_pNtDuplicateObject, hNTDLL, "NtDuplicateObject") ||
        !DoGetProc(s_pNtQueryObject, hNTDLL, "NtQueryObject"))
    {
        printf("Cannot get procedures of ntdll.dll\n");
        return EXIT_FAILURE;
    }

    int ret = DoMain(argc, wargv);

    FreeLibrary(hNTDLL);
    return ret;
}

int main(int argc, char **argv)
{
    int argc_ = 0;
    LPWSTR *wargv_ = CommandLineToArgvW(GetCommandLineW(), &argc_);
    int ret = wmain(argc_, wargv_);
    LocalFree(wargv_);
    return ret;
}
