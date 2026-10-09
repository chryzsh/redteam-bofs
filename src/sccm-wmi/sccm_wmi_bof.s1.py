r"""
sccm-wmi — OC2 wrapper for the sccm-wmi BOF (SCCM CRED-3, live WMI).

The BOF queries the live SCCM policy WMI namespace
(ROOT\ccm\policy\Machine\ActualConfig) for CCM_NetworkAccessAccount and
decrypts the NAA username/password PolicySecret blobs locally with
CryptUnprotectData, impersonating SYSTEM. It takes no arguments.
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask


class SccmWmiBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sccm-wmi",
            base_binary_name="sccm-wmi",
        )

        self.parser.description = (
            "Recover SCCM Network Access Account credentials from live WMI "
            "policy (CRED-3). Queries CCM_NetworkAccessAccount under "
            "ROOT\\ccm\\policy\\Machine\\ActualConfig and decrypts the "
            "PolicySecret blobs as SYSTEM."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  sccm-wmi\n\n"
            "Notes:\n"
            "  - Requires a high-integrity (admin) context.\n"
            "  - Runs local CryptUnprotectData as SYSTEM after impersonation.\n"
            "  - For on-disk OBJECTS.DATA recovery use sccm-disk (CRED-4).\n"
            "  - Requires an active SCCM client with a live policy namespace.\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple]:
        self.parser.parse_args(arguments)
        return []

    def run(self, arguments: List[str]):
        self.parser.parse_args(arguments)
        self.append_response("[*] Triaging SCCM live WMI policy (CRED-3)\n\n")
        super().run(arguments)
