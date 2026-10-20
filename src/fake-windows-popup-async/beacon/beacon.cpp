/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>
#include <string>
#include "beacon.h"

static uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

static uint32_t swap_endianess_short(uint16_t indata) {
    uint32_t testint = 0xaabb;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xbb) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

extern "C" BEACON_IMPEX void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
    parser->buffer = buffer;
    return;
}

extern "C" BEACON_IMPEX int BeaconDataInt(datap* parser) {
    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)swap_endianess(fourbyteint);
}

extern "C" BEACON_IMPEX short BeaconDataShort(datap* parser) {
    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);    
    parser->buffer += 2;
    parser->length -= 2;
    return (short)swap_endianess_short(retvalue);
}

extern "C" BEACON_IMPEX int BeaconDataLength(datap* parser) {
    return parser->length;
}

extern "C" BEACON_IMPEX char* BeaconDataExtract(datap* parser, int* size) {
    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    length = swap_endianess(length);

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

extern "C" BEACON_IMPEX void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    format->original = (char*)calloc(maxsz+1, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

extern "C" BEACON_IMPEX void BeaconFormatReset(formatp* format) {
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = 0;
    return;
}

extern "C" BEACON_IMPEX void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

extern "C" BEACON_IMPEX void BeaconFormatAppend(formatp* format, const char* text, int len) {
    if(format->length + len <= format->size){
        memcpy(format->buffer, text, len);
        format->buffer += len;
        format->length += len;
    }
    return;
}

extern "C" BEACON_IMPEX void BeaconFormatPrintf(formatp* format, const char* fmt, ...) {
    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, format->size - format->length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


extern "C" BEACON_IMPEX char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;
    return format->original;
}

extern "C" BEACON_IMPEX void BeaconFormatInt(formatp* format, int value) {
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length < 4) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

/* Async BOFs can print from worker threads, so serialise console output */
static SRWLOCK output_lock = SRWLOCK_INIT;

extern "C" BEACON_IMPEX void BeaconPrintf(int type, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    AcquireSRWLockExclusive(&output_lock);
    vprintf(fmt, args);
    fflush(stdout);
    ReleaseSRWLockExclusive(&output_lock);
    va_end(args);
}

extern "C" BEACON_IMPEX void BeaconOutput(int type, char* data, int len) {
    AcquireSRWLockExclusive(&output_lock);
    fwrite(data,len,1,stdout);
    fflush(stdout);
    ReleaseSRWLockExclusive(&output_lock);
}

/* Async BOF functions
 *
 * Standalone emulation: the stop job event is a manual-reset event that
 * Ctrl+C or Ctrl+Break signals, and BeaconWakeup prints a marker so you can
 * see when the BOF would have woken the implant. */

static HANDLE stop_job_event = NULL;

static BOOL WINAPI stop_job_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        SetEvent(stop_job_event);
        return TRUE;
    }
    return FALSE;
}

static BOOL CALLBACK create_stop_job_event(PINIT_ONCE, PVOID, PVOID*) {
    stop_job_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (stop_job_event != NULL)
        SetConsoleCtrlHandler(stop_job_ctrl_handler, TRUE);
    return TRUE;
}

extern "C" BEACON_IMPEX HANDLE BeaconGetStopJobEvent() {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    InitOnceExecuteOnce(&once, create_stop_job_event, NULL, NULL);
    return stop_job_event;
}

extern "C" BEACON_IMPEX void BeaconWakeup() {
    AcquireSRWLockExclusive(&output_lock);
    fputs("[wakeup]\n", stdout);
    fflush(stdout);
    ReleaseSRWLockExclusive(&output_lock);
}

/* Token Functions */

extern "C" BEACON_IMPEX BOOL BeaconUseToken(HANDLE token) {
    /* Probably needs to handle DuplicateTokenEx too */
    SetThreadToken(NULL, token);
    return TRUE;
}

extern "C" BEACON_IMPEX void BeaconRevertToken(void) {
    if (!RevertToSelf()) {
#ifdef DEBUG
        printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

extern "C" BEACON_IMPEX BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
#ifdef DEBUG
    printf("BeaconIsAdmin Called\n");
#endif
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic place holders, and if implemented into something
 * real should be just calling internal functions for your tools. */
extern "C" BEACON_IMPEX void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    return;
}

extern "C" BEACON_IMPEX BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

extern "C" BEACON_IMPEX void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

extern "C" BEACON_IMPEX void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

extern "C" BEACON_IMPEX void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    (void)CloseHandle(pInfo->hThread);
    (void)CloseHandle(pInfo->hProcess);
    return;
}

extern "C" BEACON_IMPEX BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (max < sizeof(wchar_t))
        return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}

int GetPackedArguments(int argc, const char* argv[], const char* bof_args_def, std::string& result);

extern "C" BEACON_IMPEX int BeaconInvokeStandalone(int argc, const char* argv[], const char* bof_args_def, BeaconEntryPtr entry){

    if(argc <= 0 || argv == nullptr){
        entry(nullptr, 0);
        return 0;
    }else{

        std::string packed_args;
        if(GetPackedArguments(argc, argv, bof_args_def, packed_args) >= 0)
            entry(packed_args.c_str(), packed_args.length());
    }

    return 0;
}

#endif
