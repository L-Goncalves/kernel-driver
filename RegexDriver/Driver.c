#include "Driver.h"

// base_address
PVOID g_BaseAddress = NULL;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    // Other classes can be added as needed
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Define the function prototype for ZwQuerySystemInformation
NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(
    PEPROCESS Process
);

NTSTATUS GetProcessIdByName(PCWSTR processName, PHANDLE processId) {
    ULONG bufferSize = 0x10000;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'Proc');
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePool(buffer);
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'Proc');
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    }

    if (NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (TRUE) {
            if (processInfo->ImageName.Buffer != NULL) {
                if (wcsstr(processInfo->ImageName.Buffer, processName) != NULL) {
                    *processId = processInfo->UniqueProcessId;
                    ExFreePool(buffer);
                    return STATUS_SUCCESS;
                }
            }
            if (processInfo->NextEntryOffset == 0) {
                break;
            }
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}

extern NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(
    PEPROCESS Process
);

NTSTATUS GetBaseAddress(HANDLE pid) {
    PEPROCESS targetProcess = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to get PEPROCESS from PID: 0x%X\n", pid);
        return status;
    }

    g_BaseAddress = PsGetProcessSectionBaseAddress(targetProcess);
    if (g_BaseAddress != NULL) {
        DbgPrint("Base address: 0x%p\n", g_BaseAddress);
    }
    else {
        DbgPrint("Failed to get base address.\n");
    }

    return STATUS_SUCCESS;
}


NTSTATUS GetGameProcessID(PHANDLE processId) {
    // REPLACE THIS
    return GetProcessIdByName(L"Game.exe", processId);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Set the unload routine
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Regex");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Regex");
    PDEVICE_OBJECT deviceObject = NULL;

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (NT_SUCCESS(status)) {
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(deviceObject);
        }
    }

    if (NT_SUCCESS(status)) {
        HANDLE pid;
        NTSTATUS statusPID;
        statusPID = GetGameProcessID(&pid);
        DbgPrint("Regex loaded successfully.\n");

        if (NT_SUCCESS(statusPID)) {
            DbgPrint("FOUND PID. %u\n", pid);
            GetBaseAddress(pid);
        }
        else {
            DbgPrint("NOT FOUND PID.\n");
        }


    }
    else {
        DbgPrint("Regex failed to load.\n");
    }

    return status;
}



NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Regex");
    IoDeleteSymbolicLink(&symbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("Regex unloaded successfully.\n");
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
        break;

    case IRP_MJ_DEVICE_CONTROL:
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_READ_MEMORY: {
            PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;
            status = PsLookupProcessByProcessId(memOp->ProcessId, &process);
            if (NT_SUCCESS(status)) {
                __try {
                    status = ReadMemory(process, memOp->SourceAddress, memOp->TargetAddress, memOp->Size);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("Exception occurred while reading memory: 0x%X\n", GetExceptionCode());
                    status = GetExceptionCode();
                }
                ObDereferenceObject(process);
            }
            Irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(MEMORY_OPERATION) : 0;
            break;
        }

        case IOCTL_WRITE_MEMORY: {
            PMEMORY_OPERATION memOp = (PMEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;
            status = PsLookupProcessByProcessId(memOp->ProcessId, &process);
            if (NT_SUCCESS(status)) {
                __try {
                    status = WriteMemory(process, memOp->SourceAddress, memOp->TargetAddress, memOp->Size);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("Exception occurred while writing memory: 0x%X\n", GetExceptionCode());
                    status = GetExceptionCode();
                }
                ObDereferenceObject(process);
            }
            Irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(MEMORY_OPERATION) : 0;
            break;
        }

        case IOCTL_QUERY_MEMORY_INFO: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MEMORY_INFO)) {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            PMEMORY_INFO memInfo = (PMEMORY_INFO)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS process;
            HANDLE processId = (HANDLE)memInfo->ProcessId; // Ensure this cast is correct
            status = PsLookupProcessByProcessId(processId, &process);
            if (NT_SUCCESS(status)) {
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                KAPC_STATE apc_state;

                __try {
                    KeStackAttachProcess(process, &apc_state);

                    // Perform memory query
                    status = ZwQueryVirtualMemory(ZwCurrentProcess(), memInfo->Address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);

                    if (NT_SUCCESS(status)) {
                        memInfo->MemoryInfo.BaseAddress = mbi.BaseAddress;
                        memInfo->MemoryInfo.AllocationBase = mbi.AllocationBase;
                        memInfo->MemoryInfo.AllocationProtect = mbi.AllocationProtect;
                        memInfo->MemoryInfo.RegionSize = mbi.RegionSize;
                        memInfo->MemoryInfo.State = mbi.State;
                        memInfo->MemoryInfo.Protect = mbi.Protect;
                        memInfo->MemoryInfo.Type = mbi.Type;

                        /*     DbgPrint("Region Size mbi: %llu\n", mbi.RegionSize);
                             DbgPrint("Region Size memInfo: %llu\n", memInfo->MemoryInfo.RegionSize);*/
                    }
                    else {
                        DbgPrint("ZwQueryVirtualMemory failed with status: 0x%X\n", status);
                    }
                }
                __finally {
                    KeUnstackDetachProcess(&apc_state);
                }

                ObDereferenceObject(process);
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }

            Irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(MEMORY_INFO) : 0;
            break;
        }

        case IOCTL_GET_PROCESS_ID: {
            ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
            PHANDLE processId = (PHANDLE)Irp->AssociatedIrp.SystemBuffer;

            if (outputBufferLength < sizeof(HANDLE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
            }
            else {
                status = GetGameProcessID(processId);
                Irp->IoStatus.Information = sizeof(HANDLE);
            }
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    // Complete the IRP
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS QueryVirtualMemory(PEPROCESS Process, PVOID Address, MEMORY_BASIC_INFORMATION* mbi) {
    NTSTATUS status;
    SIZE_T ReturnLength; // Use SIZE_T instead of ULONG

    // Initialize MEMORY_BASIC_INFORMATION structure
    RtlZeroMemory(mbi, sizeof(MEMORY_BASIC_INFORMATION));

    // Call ZwQueryVirtualMemory to get memory information
    status = ZwQueryVirtualMemory(Process, Address, MemoryBasicInformation, mbi, sizeof(MEMORY_BASIC_INFORMATION), &ReturnLength);

    if (!NT_SUCCESS(status)) {
        DbgPrint("ZwQueryVirtualMemory failed with status: 0x%X\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}



NTSTATUS ReadMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    SIZE_T BytesRead = 0;
    NTSTATUS status;

    // Check for valid process and address
    if (Process == NULL || SourceAddress == NULL || TargetAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Ensure size is within reasonable bounds
    if (Size == 0 || Size > MAXULONG_PTR) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Perform memory copy from user-mode process to kernel-mode buffer
        status = MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &BytesRead);

        // Check if the operation was successful
        if (!NT_SUCCESS(status)) {
            // DbgPrint("MmCopyVirtualMemory failed with status: 0x%X\n", status);
            return status;
        }

        // Check if the number of bytes read matches the requested size
        if (BytesRead != Size) {
            DbgPrint("Read size mismatch: requested 0x%X, actual 0x%X\n", (ULONG)Size, (ULONG)BytesRead);
            return STATUS_PARTIAL_COPY;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Handle exceptions if any occur during memory access
        status = GetExceptionCode();
        DbgPrint("Exception occurred during MmCopyVirtualMemory: 0x%X\n", status);
    }

    return status;
}

NTSTATUS WriteMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    SIZE_T BytesWritten;
    NTSTATUS status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &BytesWritten);
    return status;
}

