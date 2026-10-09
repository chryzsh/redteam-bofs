"""
dpapi-unprotect — OC2 wrapper for the dpapi_unprotect BOF.

The BOF calls CryptUnprotectData() in the calling user's context with a raw
DPAPI blob and (optionally) an entropy buffer. The operator supplies both as
hex strings on the command line; this wrapper hex-decodes them into bytes
and packs them as BOFArgumentEncoding.BUFFER.

BOF expects: b b   (target_blob, entropy)
"""
from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


def _hex_to_bytes(value: str, label: str) -> bytes:
    cleaned = "".join(value.split()).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise TaskInvalidArgumentsException(
            f"{label} hex must have an even number of characters (got {len(cleaned)})"
        )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise TaskInvalidArgumentsException(f"{label} is not valid hex: {exc}")


class DpapiUnprotectBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("dpapi-unprotect", base_binary_name="dpapi-unprotect")

        self.parser.description = (
            "Call CryptUnprotectData() in the current user's context on a raw "
            "DPAPI blob, with optional entropy. Prints the decrypted plaintext "
            "as hex, ASCII, and UTF-16LE."
        )

        self.parser.add_argument(
            "blob",
            help="DPAPI blob as a hex string (no SCD entropy prefix — strip it first).",
        )
        self.parser.add_argument(
            "--entropy",
            "-e",
            default="",
            help="Optional entropy as a hex string (e.g. the 16-byte prefix SCD stores).",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  dpapi-unprotect 01000000d08c9ddf...   # no entropy\n"
            "  dpapi-unprotect 01000000d08c9ddf... -e 5f7531c034393c60adb7440063f2ee46\n\n"
            "Notes:\n"
            "  - Run from a user-context implant (the user who originally protected the data).\n"
            "  - From SYSTEM you must impersonate that user first; DPAPI is per-user.\n"
            "  - The blob argument is the pure DPAPI structure starting with the version DWORD\n"
            "    (0x01000000) and provider GUID (d08c9ddf-0115-d111-8c7a-00c04fc297eb).\n"
            "    If your stored blob has a custom prefix (e.g. SCD's 16-byte entropy),\n"
            "    strip those bytes and pass them via --entropy.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)
        parsed = self.parser.parse_args(arguments)
        blob = _hex_to_bytes(parsed.blob, "blob")
        if len(blob) < 24:
            raise TaskInvalidArgumentsException(
                f"blob is too short to be a DPAPI structure ({len(blob)} bytes)"
            )
        # entropy is optional; only validate if supplied
        if parsed.entropy:
            _hex_to_bytes(parsed.entropy, "entropy")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, bytes]]:
        parsed = self.parser.parse_args(arguments)
        blob_bytes = _hex_to_bytes(parsed.blob, "blob")
        entropy_bytes = (
            _hex_to_bytes(parsed.entropy, "entropy") if parsed.entropy else b""
        )
        # BOF expects: b b   (target_blob, entropy)
        return [
            (BOFArgumentEncoding.BUFFER, blob_bytes),
            (BOFArgumentEncoding.BUFFER, entropy_bytes),
        ]
