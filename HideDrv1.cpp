#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>

/*
    This driver hider is made and tested for Windows 11 21H2 RTM. Tested on 4/4/2022.
    This hides your driver from:
    MmUnloadedDrivers
    PsLoadedModuleList
    PiDDBCacheTable
    Driver object list

    You'll have to handle these yourself:
    ExpCovUnloadedDrivers (very rarely used)
    MmVerifierData
    .. and anything else
*/
//0xb0 bytes (sizeof)
typedef struct _MM_DRIVER_VERIFIER_DATA
{
    ULONG Level;                                                            //0x0
    volatile ULONG RaiseIrqls;                                              //0x4
    volatile ULONG AcquireSpinLocks;                                        //0x8
    volatile ULONG SynchronizeExecutions;                                   //0xc
    volatile ULONG AllocationsAttempted;                                    //0x10
    volatile ULONG AllocationsSucceeded;                                    //0x14
    volatile ULONG AllocationsSucceededSpecialPool;                         //0x18
    ULONG AllocationsWithNoTag;                                             //0x1c
    ULONG TrimRequests;                                                     //0x20
    ULONG Trims;                                                            //0x24
    ULONG AllocationsFailed;                                                //0x28
    volatile ULONG AllocationsFailedDeliberately;                           //0x2c
    volatile ULONG AllocationFreed;                                         //0x30
    volatile ULONG Loads;                                                   //0x34
    volatile ULONG Unloads;                                                 //0x38
    ULONG UnTrackedPool;                                                    //0x3c
    ULONG UserTrims;                                                        //0x40
    volatile ULONG CurrentPagedPoolAllocations;                             //0x44
    volatile ULONG CurrentNonPagedPoolAllocations;                          //0x48
    ULONG PeakPagedPoolAllocations;                                         //0x4c
    ULONG PeakNonPagedPoolAllocations;                                      //0x50
    volatile ULONGLONG PagedBytes;                                          //0x58
    volatile ULONGLONG NonPagedBytes;                                       //0x60
    ULONGLONG PeakPagedBytes;                                               //0x68
    ULONGLONG PeakNonPagedBytes;                                            //0x70
    volatile ULONG BurstAllocationsFailedDeliberately;                      //0x78
    ULONG SessionTrims;                                                     //0x7c
    volatile ULONG OptionChanges;                                           //0x80
    volatile ULONG VerifyMode;                                              //0x84
    struct _UNICODE_STRING PreviousBucketName;                              //0x88
    volatile ULONG ExecutePoolTypes;                                        //0x98
    volatile ULONG ExecutePageProtections;                                  //0x9c
    volatile ULONG ExecutePageMappings;                                     //0xa0
    volatile ULONG ExecuteWriteSections;                                    //0xa4
    volatile ULONG SectionAlignmentFailures;                                //0xa8
    volatile ULONG IATInExecutableSection;                                  //0xac
} MM_DRIVER_VERIFIER_DATA, * PMM_DRIVER_VERIFIER_DATA;

//0xa0 bytes (sizeof)
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Frozen : 2;                                                    //0x6e
        USHORT HotPatch : 1;                                                  //0x6e
        USHORT Unused : 6;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    union
    {
        VOID* Spare;                                                        //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
    };
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
} _KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

ULONG64 count = 0;

__forceinline void log_success(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[SUCCESS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

__forceinline void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[DEBUG] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

__forceinline void log_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

__forceinline PVOID get_ntoskrnl_export(PCWSTR export_name)
{
    UNICODE_STRING export_string;
    RtlInitUnicodeString(&export_string, export_name);

    return MmGetSystemRoutineAddress(&export_string);
}

__forceinline PKLDR_DATA_TABLE_ENTRY get_ldr_entry(PCWSTR base_dll_name)
{
    UNICODE_STRING base_dll_name_string;
    RtlInitUnicodeString(&base_dll_name_string, base_dll_name);

    PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)get_ntoskrnl_export(L"PsLoadedModuleList");

    /* Is PsLoadedModuleList null? */
    if (!PsLoadedModuleList)
    {
        return NULL;
    }

    /* Start iterating at LIST_ENTRY.Flink */
    PKLDR_DATA_TABLE_ENTRY iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;

    /* If LIST_ENTRY.Flink = beginning, then it's the last entry */
    while ((PLIST_ENTRY)iter_ldr_entry != PsLoadedModuleList)
    {
        if (!RtlCompareUnicodeString(&iter_ldr_entry->BaseDllName, &base_dll_name_string, TRUE))
        {
            return iter_ldr_entry;
        }

        /* Move on to the next entry */
        iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)iter_ldr_entry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

ULONG64 MmVerifierData_offset = 0xC29E20;
ULONG64 MiProcessLoaderEntry_offset = 0x209FEC;
ULONG64 PiDDBLock_offset = 0xC45E20;
ULONG64 PiDDBCacheList_Offset = 0xD3D940;
ULONG64 PiDDBCacheTable_offset = 0xD3DD50;
ULONG64 g_KernelHashBucketList_offset = 0xBC080;
ULONG64 g_HashCacheLock_offset = 0x31FC0;
ULONG64 MmLastUnloadedDriver_offset = 0xC29708;
ULONG64 MmUnloadedDrivers_offset = 0xC29710;
ULONG64 PsLoadedModuleResource_offset = 0xC29B20;
ULONG64 PoolBigPageTable_offset = 0xC15710;
ULONG64 PoolBigPageTableSize_offset = 0xC15728;

// entry remover unimplemented
ULONG64 MiLargePageDriverBuffer_offset = 0xC29720;
ULONG64 MiLargePageDriverBufferLength_offset = 0xD69158;

// Set this yourself
ULONG timestamp = 0;

typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
} PiDDBCacheEntry, * NPiDDBCacheEntry;

__forceinline BOOLEAN remove_PiDDBCacheTable_entry(PUNICODE_STRING driver_name, ULONG timestamp)
{
    PVOID PiDDBLock = (PVOID)((ULONG64)get_ldr_entry(L"ntosknrl.exe") + (ULONG64)PiDDBLock_offset);
    PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)((ULONG64)get_ldr_entry(L"ntosknrl.exe") + (ULONG64)PiDDBCacheTable_offset);

    if (!ExAcquireResourceExclusiveLite(PiDDBLock, TRUE))
    {
        log_error("Couldn't get PiDDBLock.\n");
    }

    PiDDBCacheEntry search_entry = { 0 };
    search_entry.DriverName = *driver_name;
    search_entry.TimeDateStamp = timestamp;

    PiDDBCacheEntry* result_entry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&search_entry);
    if (!result_entry)
    {
        log_error("Failed to find driver \"%wZ\" with timestamp %X within PiDDBCacheTable.\n", driver_name, timestamp);
        ExReleaseResourceLite(PiDDBLock);
        return FALSE;
    }

    PLIST_ENTRY previous = result_entry->List.Blink;
    PLIST_ENTRY next = result_entry->List.Flink;
    
    previous->Flink = next;
    next->Blink = previous;

    ExReleaseResourceLite(PiDDBLock);

    if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, result_entry))
    {
        log_error("Unlinked driver entry from PiDDBCacheTable, but failed to delete it.\n");
        return FALSE;
    }

    PiDDBCacheTable->DeleteCount--;

    ExReleaseResourceLite(PiDDBLock);

    return TRUE;
}

#define MI_UNLOADED_DRIVERS 50
typedef struct _MM_UNLOADED_DRIVER
{
    UNICODE_STRING 	Name;
    PVOID 			ModuleStart;
    PVOID 			ModuleEnd;
    ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

__forceinline BOOLEAN is_MmUnloadedDrivers_empty(PMM_UNLOADED_DRIVER Entry)
{
    if (Entry->Name.MaximumLength == 0 ||
        Entry->Name.Length == 0 ||
        Entry->Name.Buffer == NULL)
    {
        return TRUE;
    }

    return FALSE;
}

__forceinline BOOLEAN is_MmUnloadedDrivers_filled(PMM_UNLOADED_DRIVER MmUnloadedDrivers)
{
    for (ULONG i = 0; i < MI_UNLOADED_DRIVERS; ++i)
    {
        if (is_MmUnloadedDrivers_empty(&MmUnloadedDrivers[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}

__forceinline BOOLEAN remove_MmUnloadedDrivers_entry(PUNICODE_STRING driver_name)
{
    PMM_UNLOADED_DRIVER MmUnloadedDrivers = (PMM_UNLOADED_DRIVER)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + MmUnloadedDrivers_offset);
    PULONG				MmLastUnloadedDriver = (PULONG)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + MmLastUnloadedDriver_offset);
    
    PVOID PsLoadedModuleResource = (PVOID)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + PsLoadedModuleResource_offset);

    if (!ExAcquireResourceExclusiveLite(PsLoadedModuleResource, TRUE))
    {
        log_error("Couldn't get PsLoadedModuleResource.\n");
        return FALSE;
    }

    BOOLEAN modified = FALSE;
    BOOLEAN filled = is_MmUnloadedDrivers_filled(MmUnloadedDrivers);

    for (ULONG i = 0; i < MI_UNLOADED_DRIVERS; ++i)
    {
        PMM_UNLOADED_DRIVER current_entry = &MmUnloadedDrivers[i];

        if (modified)
        {
            PMM_UNLOADED_DRIVER previous_entry = &MmUnloadedDrivers[i - 1];

            if (i == MI_UNLOADED_DRIVERS - 1UL)
            {
                RtlFillMemory(current_entry, sizeof(MM_UNLOADED_DRIVER), 0);
            }
        }
        else if (RtlEqualUnicodeString(driver_name, &current_entry->Name, TRUE))
        {

            PVOID BufferPool = current_entry->Name.Buffer;
            RtlFillMemory(current_entry, sizeof(MM_UNLOADED_DRIVER), 0);
            ExFreePoolWithTag(BufferPool, 'TDmM');

            *MmLastUnloadedDriver = (filled ? MI_UNLOADED_DRIVERS : *MmLastUnloadedDriver) - 1;
            modified = TRUE;
        }
    }
    if (modified)
    {
        ULONG64 previous_time = 0;

        
        for (LONG index = MI_UNLOADED_DRIVERS - 2; index >= 0; --index)
        {
            PMM_UNLOADED_DRIVER current_entry = &MmUnloadedDrivers[index];
            if (is_MmUnloadedDrivers_empty(current_entry))
            {
                continue;
            }

            if (previous_time != 0 && current_entry->UnloadTime > previous_time)
            {
                current_entry->UnloadTime = previous_time - 100;
            }

            previous_time = current_entry->UnloadTime;
        }

        remove_MmUnloadedDrivers_entry(driver_name, FALSE);
    }

    return modified ? TRUE : FALSE;
}

typedef struct _HashBucketEntry
{
    struct _HashBucketEntry* Next;
    UNICODE_STRING DriverName;
    ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;

__forceinline BOOLEAN remove_KernelHashBucketList_entry(PUNICODE_STRING driver_name)
{
    HashBucketEntry* g_KernelHashBucketList = (HashBucketEntry*)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + g_KernelHashBucketList_offset);
    PVOID g_HashCacheLock = (PVOID)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + g_HashCacheLock_offset);

    if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, TRUE))
    {
        log_error("Failed to get g_HashCacheLock.\n");
        return FALSE;
    }

    HashBucketEntry* current_entry = g_KernelHashBucketList;
    HashBucketEntry* previous_entry = g_KernelHashBucketList;

    while (current_entry)
    {
        if (RtlCompareUnicodeString(&current_entry->DriverName, driver_name, FALSE))
        {
            log_success("Found driver \"%wZ\" within g_KernelHashBucketList.\n", driver_name);
            previous_entry->Next = current_entry->Next;
            ExReleaseResourceLite(g_HashCacheLock);
            return TRUE;
        }

        if (current_entry->Next == g_KernelHashBucketList)
        {
            log_error("Couldn't find driver \"%wZ\" within g_KernelHashBucketList.\n", driver_name);
            ExReleaseResourceLite(g_HashCacheLock);
            return FALSE;
        }

        if (!RtlCompareUnicodeString(&current_entry->DriverName, driver_name, FALSE))
        {
            continue;
        }

        previous_entry = current_entry;
        current_entry = current_entry->Next;
    }

    log_error("Couldn't find driver \"%wZ\" within g_KernelHashBucketList.\n", driver_name);
    ExReleaseResourceLite(g_HashCacheLock);
    return FALSE;
}

//0x20 bytes (sizeof)
typedef struct _POOL_TRACKER_BIG_PAGES
{
    volatile ULONGLONG Va;                                                  //0x0
    ULONG Key;                                                              //0x8
    ULONG Pattern : 8;                                                        //0xc
    ULONG PoolType : 12;                                                      //0xc
    ULONG SlushSize : 12;                                                     //0xc
    ULONGLONG NumberOfBytes;                                                //0x10
    PEPROCESS ProcessBilled;                                        //0x18
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

#define POOL_BIG_TABLE_ENTRY_FREE   0x1

// Also returns true if not in big pool tracker
__forceinline BOOLEAN remove_PoolBigPageTracker_entry(ULONG64 base_address)
{
    POOL_TRACKER_BIG_PAGES* pool_big_page_tracker = (POOL_TRACKER_BIG_PAGES*)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + PoolBigPageTable_offset);
    PULONG64 pool_big_page_tracker_size = (PULONG64*)((ULONG64)get_ldr_entry(L"ntoskrnl.exe") + PoolBigPageTableSize_offset);

    for (ULONG64 i = 0; i < *pool_big_page_tracker_size; i++)
    {
      /*if (pool_big_page_tracker[i].Va & POOL_BIG_TABLE_ENTRY_FREE)
        {
            continue;
        }
      */

        if (pool_big_page_tracker[i].Va = base_address || pool_big_page_tracker[i].Va == (base_address + 0x1ULL))
        {
            pool_big_page_tracker[i].Va = 0x1ULL;
            pool_big_page_tracker[i].NumberOfBytes = 0x0ULL;
            return TRUE;
        }
    }

    return TRUE;
}

NTSTATUS GsDriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    // Remove driver from all 4 tables/lists
    if (!remove_MmUnloadedDrivers_entry(&driver_object->DriverName))
    {
        log_error("Failed to remove driver \"%wZ\" from MmUnloadedDrivers.\n", &driver_object->DriverName);
        return STATUS_UNSUCCESSFUL;
    }

    if (!remove_PiDDBCacheTable_entry(&driver_object->DriverName, timestamp))
    {
        log_error("Failed to remove driver \"%wZ\" from PiDDBCacheTable.\n", &driver_object->DriverName);
        return STATUS_UNSUCCESSFUL;
    }

    if (!remove_KernelHashBucketList_entry(&driver_object->DriverName))
    {
        log_error("Failed to remove driver \"%wZ\" from g_KernelHashBucketList.\n", &driver_object->DriverName);
        return STATUS_UNSUCCESSFUL;
    }

    PKLDR_DATA_TABLE_ENTRY current_driver_ldr_entry = driver_object->DriverSection;
    
    if (!remove_PoolBigPageTracker_entry((ULONG64)current_driver_ldr_entry->DllBase))
    {
        log_error("Failed to remove driver with base address %llX from PoolBigPageTracker.\n", current_driver_ldr_entry->DllBase);
        return STATUS_UNSUCCESSFUL;
    }

    log_success("Removed driver \"%wZ\" with base address %llX from:\n\t->MmUnloadedDrivers\n\t->PiDDBCacheTable\n\t->g_KernelHashBucketList\n\t->PoolBigPageTracker\n\n", 
        driver_object->DriverName, current_driver_ldr_entry->DllBase);

    // Mark this driver object temporary, so it can be deleted soon.
    ObMakeTemporaryObject(driver_object);
    log_success("Marked current driver object temporary for deletion.\n");

    // Remove loader entry from PsLoadedModuleList
    VOID(NTAPI * MiProcessLoaderEntry)(PKLDR_DATA_TABLE_ENTRY LdrEntry, BOOLEAN Insert);
    

    MiProcessLoaderEntry = ((ULONG64)current_driver_ldr_entry + MiProcessLoaderEntry_offset);
    MiProcessLoaderEntry((PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection, FALSE);
    log_success("Removed loader entry from PsLoadedModuleList.\n");

    return STATUS_SUCCESS;
}
