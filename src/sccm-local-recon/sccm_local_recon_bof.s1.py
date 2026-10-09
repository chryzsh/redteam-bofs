r"""
sccm-local-recon — OC2 wrapper for the sccm-local-recon BOF (SCCM RECON-7, local client).

Enumerates SCCM local client paths (CCM logs, ccmcache, ccmsetup), lists the
client cache with per-user read/write permissions, reads the ManagementPoints
registry value, and scrapes the CCM logs for candidate UNC paths and URLs.
Runs in the current user's context. It takes no arguments.
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask


class SccmLocalReconBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "sccm-local-recon",
            base_binary_name="sccm-local-recon",
        )

        self.parser.description = (
            "Local SCCM client reconnaissance (RECON-7). Enumerates CCM logs, "
            "ccmcache, and ccmsetup paths with per-user permissions, reads the "
            "ManagementPoints registry value, and scrapes the logs for UNC "
            "paths and URLs."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  sccm-local-recon\n\n"
            "Notes:\n"
            "  - Runs in the current user's context (no SYSTEM impersonation).\n"
            "  - Read-only: file enumeration, registry read, and log scanning.\n"
            "  - For credential recovery use sccm-wmi (CRED-3) or sccm-disk (CRED-4).\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple]:
        self.parser.parse_args(arguments)
        return []

    def run(self, arguments: List[str]):
        self.parser.parse_args(arguments)
        self.append_response("[*] Triaging SCCM local client (RECON-7)\n\n")
        super().run(arguments)
