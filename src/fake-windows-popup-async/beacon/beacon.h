/*
 *
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Additional BOF resources are available here:
 *   - https://github.com/Cobalt-Strike/bof_template
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 *    7/18/2023: Added BeaconInformation API for 4.9
 *    7/31/2023: Added Key/Value store APIs for 4.9
 *                  BeaconAddValue, BeaconGetValue, and BeaconRemoveValue
 *    8/31/2023: Added Data store APIs for 4.9
 *                  BeaconDataStoreGetItem, BeaconDataStoreProtectItem,
 *                  BeaconDataStoreUnprotectItem, and BeaconDataStoreMaxEntries
 *    9/01/2023: Added BeaconGetCustomUserData API for 4.9
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef BUILD_BEACON
#define BEACON_IMPEX __declspec(dllimport)
#else
#define BEACON_IMPEX __declspec(dllexport)
#endif

/* data API */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

BEACON_IMPEX void    BeaconDataParse(datap * parser, char * buffer, int size);
BEACON_IMPEX char *  BeaconDataPtr(datap * parser, int size);
BEACON_IMPEX int     BeaconDataInt(datap * parser);
BEACON_IMPEX short   BeaconDataShort(datap * parser);
BEACON_IMPEX int     BeaconDataLength(datap * parser);
BEACON_IMPEX char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

BEACON_IMPEX void    BeaconFormatAlloc(formatp * format, int maxsz);
BEACON_IMPEX void    BeaconFormatReset(formatp * format);
BEACON_IMPEX void    BeaconFormatAppend(formatp * format, const char * text, int len);
BEACON_IMPEX void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
BEACON_IMPEX char *  BeaconFormatToString(formatp * format, int * size);
BEACON_IMPEX void    BeaconFormatFree(formatp * format);
BEACON_IMPEX void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d



BEACON_IMPEX void   BeaconOutput(int type, char * data, int len);
BEACON_IMPEX void   BeaconPrintf(int type, const char * fmt, ...);


/* Token Functions */
BEACON_IMPEX BOOL   BeaconUseToken(HANDLE token);
BEACON_IMPEX void   BeaconRevertToken();
BEACON_IMPEX BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
BEACON_IMPEX void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
BEACON_IMPEX void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
BEACON_IMPEX void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
BEACON_IMPEX BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
BEACON_IMPEX void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
BEACON_IMPEX BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Beacon Information */
/*
 *  ptr  - pointer to the base address of the allocated memory.
 *  size - the number of bytes allocated for the ptr.
 */
typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

/*
 *  sleep_mask_ptr        - pointer to the sleep mask base address
 *  sleep_mask_text_size  - the sleep mask text section size
 *  sleep_mask_total_size - the sleep mask total memory size
 *
 *  beacon_ptr   - pointer to beacon's base address
 *                 The stage.obfuscate flag affects this value when using CS default loader.
 *                    true:  beacon_ptr = allocated_buffer - 0x1000 (Not a valid address)
 *                    false: beacon_ptr = allocated_buffer (A valid address)
 *                 For a UDRL the beacon_ptr will be set to the 1st argument to DllMain
 *                 when the 2nd argument is set to DLL_PROCESS_ATTACH.
 *  sections     - list of memory sections beacon wants to mask. These are offset values
 *                 from the beacon_ptr and the start value is aligned on 0x1000 boundary.
 *                 A section is denoted by a pair indicating the start and end offset values.
 *                 The list is terminated by the start and end offset values of 0 and 0.
 *  heap_records - list of memory addresses on the heap beacon wants to mask.
 *                 The list is terminated by the HEAP_RECORD.ptr set to NULL.
 *  mask         - the mask that beacon randomly generated to apply
 */
typedef struct {
    char  * sleep_mask_ptr;
    DWORD   sleep_mask_text_size;
    DWORD   sleep_mask_total_size;

    char  * beacon_ptr;
    DWORD * sections;
    HEAP_RECORD * heap_records;
    char    mask[MASK_SIZE];
} BEACON_INFO;

BEACON_IMPEX void   BeaconInformation(BEACON_INFO * info);

/* Key/Value store functions
 *    These functions are used to associate a key to a memory address and save
 *    that information into beacon.  These memory addresses can then be
 *    retrieved in a subsequent execution of a BOF.
 *
 *    key - the key will be converted to a hash which is used to locate the
 *          memory address.
 *
 *    ptr - a memory address to save.
 *
 * Considerations:
 *    - The contents at the memory address is not masked by beacon.
 *    - The contents at the memory address is not released by beacon.
 *
 */
BEACON_IMPEX BOOL BeaconAddValue(const char * key, void * ptr);
BEACON_IMPEX void * BeaconGetValue(const char * key);
BEACON_IMPEX BOOL BeaconRemoveValue(const char * key);

/* Beacon Data Store functions
 *    These functions are used to access items in Beacon's Data Store.
 *    BeaconDataStoreGetItem returns NULL if the index does not exist.
 *
 *    The contents are masked by default, and BOFs must unprotect the entry
 *    before accessing the data buffer. BOFs must also protect the entry
 *    after the data is not used anymore.
 *
 */

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
    int type;
    DWORD64 hash;
    BOOL masked;
    char* buffer;
    size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

BEACON_IMPEX PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
BEACON_IMPEX void BeaconDataStoreProtectItem(size_t index);
BEACON_IMPEX void BeaconDataStoreUnprotectItem(size_t index);
BEACON_IMPEX size_t BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
BEACON_IMPEX char * BeaconGetCustomUserData();

/* Async BOF API
 *    Outflank async BOF spec (https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/).
 *    The C2 runs the async BOF entry point on its own thread.
 *
 *    BeaconWakeup          - ask the implant to wake from sleep and send queued
 *                            output now instead of at the next check-in.
 *    BeaconGetStopJobEvent - event handle the C2 signals when the operator stops
 *                            the job. The BOF must return soon after it is signaled.
 *                            NULL means the C2 does not run this BOF as async.
 *
 *    A C2 without these APIs may leave the import unresolved, so check the
 *    address before calling it. Read it through a volatile local, GCC drops a
 *    plain `BeaconGetStopJobEvent != nullptr` check (see README).
 */
BEACON_IMPEX void   BeaconWakeup();
BEACON_IMPEX HANDLE BeaconGetStopJobEvent();

typedef void (*BeaconEntryPtr)(const char* data, int len);

BEACON_IMPEX int BeaconInvokeStandalone(int argc, const char* argv[], const char* bof_args_def, BeaconEntryPtr entry);

#if !defined(_MSC_VER) && !defined(__clang__)
    #define BEACON_DISCARD __attribute__((section(".discard")))
    #define BEACON_DISCARD_DATA __attribute__((section(".discard_data")))
#else
    #pragma section(".discard_data", read, write)
    //#pragma code_seg(".discard")
    #define BEACON_DISCARD __declspec(code_seg(".discard"))
    #define BEACON_DISCARD_DATA __declspec(allocate(".discard_data"))
#endif

#if defined(BOF_PE_DLL)
    /* DLL mode. The BOF-PE is linked as a DLL that exports go, which is the
     * form OC2 loads as a BOF-PE (.dll). The loader (the C2, or loader.exe for
     * standalone tests) calls the DLL entry point with DLL_PROCESS_ATTACH.
     * That entry point is the CRT's DLL startup (DllMainCRTStartup for MinGW,
     * _DllMainCRTStartup for MSVC/clang-cl), which initializes the CRT and runs
     * the global constructors. Static destructors are registered in the DLL's
     * own exit table and run on DLL_PROCESS_DETACH, never in the host process
     * exit table. BEACON_INIT therefore has nothing left to do, and there is no
     * main or BeaconInvokeStandalone import. Run the DLL standalone with
     * loader.exe <name>.dll <fmt> <args>. */
    #define BEACON_INIT ((void)0)

    /* Keeps the BEACON_MAIN(fmt, entry) line valid in DLL mode. It emits no
     * code or data. fmt documents the argument format for loader.exe. */
    #define BEACON_MAIN(fmt, entry) \
        typedef char __beacon_main_fmt_check[sizeof(fmt) > 0 ? 1 : -1];

#else /* EXE mode */

#if !defined(_MSC_VER) && !defined(__clang__)
    /* __main runs the global constructors, and they (and libstdc++'s own
     * statics) register their destructors with atexit, which MinGW forwards
     * to the process-wide msvcrt exit table. The C2 frees this image after go
     * returns, so the host process would call into freed memory when it
     * exits. Point this image's atexit import at a stub first, so those
     * registrations stay local. Destructors of statics never run under a C2. */
    extern void* __MINGW_IMP_SYMBOL(_crt_atexit);
    extern void __main(void);

    static inline int __cdecl __beacon_atexit(void (__cdecl* func)(void)) {
        (void)func;
        return 0;
    }

    static inline void __beacon_init(void) {
        DWORD old = 0;
        if (VirtualProtect(&__MINGW_IMP_SYMBOL(_crt_atexit), sizeof(void*), PAGE_READWRITE, &old)) {
            __MINGW_IMP_SYMBOL(_crt_atexit) = (void*)__beacon_atexit;
            VirtualProtect(&__MINGW_IMP_SYMBOL(_crt_atexit), sizeof(void*), old, &old);
        }
        __main();
    }
    #define BEACON_INIT if(__beacon_init_crt) __beacon_init()
#else
    extern void __scrt_initialize_crt(int module_type);
    #define BEACON_INIT if(__beacon_init_crt) __scrt_initialize_crt(1)
#endif

#define BEACON_MAIN(fmt, entry) \
    bool __beacon_init_crt = true; \
    const char BEACON_DISCARD_DATA arg_fmt[] = fmt; \
    BEACON_DISCARD int main(int argc, const char* argv[]) { \
        __beacon_init_crt = false; \
        return BeaconInvokeStandalone(argc, argv, arg_fmt, entry); \
    }

    extern bool __beacon_init_crt;

#endif /* BOF_PE_DLL */

#ifdef __cplusplus
}
#endif
